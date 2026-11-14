// PowerlogProbe v1.3.0 - RELEASE
// =============================================================================
// What this is
//   A minimal, permanent write filter for com.apple.aggregated (PowerlogCore).
//   It drops ONLY pure diagnostic telemetry before the final SQLite INSERT and
//   leaves everything else - especially Settings > Battery per-App energy
//   percentages - completely stock.
//
// Verified on device 2026-11-14 (planC3.log, 21:07:15 - 21:31:12):
//   153 distinct entryKeys: 100 PASS / 53 BLOCK, 10500 writes, 31.5% blocked.
//   cs=0/0 batch=0/0 arr=0/0 unknown=0 => no bypass path, no unknown payload.
//   All 11 PLAccountingOperator_* keys, all 6 PLApplicationAgent_* keys, all
//   14 PLBatteryAgent_* keys and every hardware/state Agent were allowed.
//
// Why a blacklist and not a whitelist
//   PLAN A / PLAN B blocked 97 hardware/state Agents. Those EventForward_*
//   events are the inputs PLAccountingQualificationManager uses to decide
//   WHICH APP owns WHICH energy node. Energy totals stayed, but
//   QualificationEvents fell 696 -> 157 rows/hour and
//   Aggregate_QualificationEnergy 11 -> 0, so per-App percentages went wrong.
//   The 99% CPU bursts are a 3-second batch flush of RAW energy rows, not the
//   hourly aggregate rollup. Blocking that flush only makes the data worse.
//
// Why SQL layer only
//   PLCoreStorage is never touched, so rowids, completion blocks, the
//   qualification state machine and hourly aggregates run 100% stock.
//   Only the final INSERT is skipped. Short-circuited writes return a
//   synthetic non-zero rowid so callers still see "write succeeded";
//   setWriteToDB: is NEVER called (that dirtied entries in PLAN A).
//
// This RELEASE build
//   - NO log file, NO counters, NO timestamps, NO mutex: zero disk I/O from
//     this tweak. v1.2.0's planC3.log instrumentation is entirely removed.
//   - NO mode flags: behaviour is fixed. Only two emergency flags remain,
//     checked once in ctor, which make every hook completely inert:
//       /var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL
//       /var/mobile/Documents/PowerlogProbe/DISABLED
//     Create an empty file then kickstart -k system/com.apple.aggregated.
//   - Fail-open: unknown payloads and missing methods always pass through.
//
// HARD CONSTRAINTS
//   - ZERO substrate/ellekit LINK dependency: no Logos hooking directives,
//     no MSHookFunction. Pure objc/runtime class_replaceMethod + %ctor.
//   - NO Foundation / UIKit link; NSString/NSArray reached via objc_msgSend.
//   - NO polling / timer / dispatch_after.
// =============================================================================

#import <objc/runtime.h>
#import <objc/message.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

#define kFlagAll "/var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL"
#define kFlagOff "/var/mobile/Documents/PowerlogProbe/DISABLED"

// Build tag, kept alive for the CI strings assertion. Never read at runtime.
static const char kBuildTag[] __attribute__((used)) =
    "PowerlogProbe 1.3.0 RELEASE C3-clean SQL-only no-log";

static int g_passthrough = 0;
static unsigned long long g_fake = 0;

// ---------------------------------------------------------------------------
// Deny list: pure diagnostic / high-volume telemetry ONLY.
// Deliberately ABSENT: PLWifiAgent_, PLBBAgent_, PLDisplayAgent_,
// PLAudioAgent_, PLXPCAgent_, PLXPCService_, PLBluetoothAgent_,
// PLNetworkAgent_, PLVideoAgent_, PLBatteryAgent_, PLApplicationAgent_,
// PLAccountingOperator_ - these are per-App energy attribution inputs.
// 120s growth probe: CoalitionMemory 84, Assertion 67, IOReport 56 + 14,
// ProcessMonitor, Rendering are the only high-volume pure-diagnostic tables;
// all of them are covered below. Nothing else is worth blocking.
// ---------------------------------------------------------------------------
static const char *kDeny[] = {
    "PLPowerAssertionAgent_",
    "PLCoalitionAgent_",
    "PLIOReportAgent_",
    "PLPerformanceAgent_",
    "PLCoreDuetAgent_",
    "PLEduAgent_",
    "PLSiriAgent_",
    "PLIdentityServicesAgent_",
    "PLPushAgent_",
    "PLMDNSAgent_",
    "PLButtonAgent_",
    "PLProximityAgent_",
    "PLSCDynamicStoreAgent_",
    "PLConfigAgent_",
    "PLLocaleAgent_",
    "PLSMCAgent_",
    "PLSpringBoardAgent_",
    "PLRenderingAgent_",
    "PLProcessMonitorAgent_EventPoint_",
    "PLProcessMonitorAgent_EventBackward_",
    "PPT",
    "ConfigMetrics_",
    "LocaleMetrics_",
    "WifiMetrics_",
    "DisplayMetrics_",
};

// ---------------------------------------------------------------------------
// objc_msgSend shims (zero Foundation link)
// ---------------------------------------------------------------------------
typedef id           (*msg_id)(id, SEL);
typedef const char * (*msg_cstr)(id, SEL);
typedef unsigned long(*msg_ulong)(id, SEL);
typedef id           (*msg_id_ulong)(id, SEL, unsigned long);
typedef void         (*msg_void_id)(id, SEL, id);
typedef long long    (*orig_single_fn)(id, SEL, id);
typedef void         (*orig_void_id_fn)(id, SEL, id);

static SEL g_selEntryKey, g_selUTF8, g_selCount, g_selObjAt, g_selAdd, g_selArray;
static Class g_clsMutableArray;
static orig_single_fn   g_origWriteEntry = NULL;
static orig_void_id_fn  g_origWriteArray = NULL;

// -[PLEntry entryKey] -> NSString -> UTF8String. Never retains anything.
static const char *entry_key(id entry) {
    if (!entry) return NULL;
    Class c = object_getClass(entry);
    if (!c || !class_respondsToSelector(c, g_selEntryKey)) return NULL;
    id k = ((msg_id)objc_msgSend)(entry, g_selEntryKey);
    if (!k) return NULL;
    Class kc = object_getClass(k);
    if (!kc) return NULL;
    if (!class_respondsToSelector(kc, g_selUTF8)) {
        if (!class_respondsToSelector(kc, g_selEntryKey)) return NULL;
        k = ((msg_id)objc_msgSend)(k, g_selEntryKey);
        if (!k) return NULL;
        kc = object_getClass(k);
        if (!kc || !class_respondsToSelector(kc, g_selUTF8)) return NULL;
    }
    return ((msg_cstr)objc_msgSend)(k, g_selUTF8);
}

static int denied(const char *k) {
    if (!k || !*k) return 0;
    for (size_t i = 0; i < sizeof(kDeny) / sizeof(kDeny[0]); i++)
        if (strncmp(k, kDeny[i], strlen(kDeny[i])) == 0) return 1;
    return 0;
}

// A legal-looking, never-colliding rowid: callers keep their downstream logic.
static long long fake_rowid(void) {
    return (long long)(0x4000000000000000ULL + __sync_add_and_fetch(&g_fake, 1));
}

// 1 = perform the real write. Fail open on anything unexpected.
static int should_write(id entry) {
    if (g_passthrough || !entry) return 1;
    const char *k = entry_key(entry);
    if (!k) return 1;
    return denied(k) ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Hook 1: -[PLSQLiteConnection writeEntry:]  (q24@0:8@16)
// ---------------------------------------------------------------------------
static long long hook_writeEntry(id self, SEL _cmd, id entry) {
    if (should_write(entry) && g_origWriteEntry)
        return g_origWriteEntry(self, _cmd, entry);
    // Either a denied entry or a missing original: still return a legal rowid.
    return fake_rowid();
}

// ---------------------------------------------------------------------------
// Hook 2: -[PLSQLiteConnection writeArrayEntries:]  (v24@0:8@16)
// Filtered array still goes to the original so all side effects stay intact.
// ---------------------------------------------------------------------------
static void hook_writeArrayEntries(id self, SEL _cmd, id entries) {
    if (!g_origWriteArray) return;
    if (g_passthrough || !entries ||
        !class_respondsToSelector(object_getClass(entries), g_selCount) ||
        !g_clsMutableArray) {
        g_origWriteArray(self, _cmd, entries);
        return;
    }
    unsigned long n = ((msg_ulong)objc_msgSend)(entries, g_selCount);
    id filtered = ((msg_id)objc_msgSend)((id)g_clsMutableArray, g_selArray);
    if (!filtered) { g_origWriteArray(self, _cmd, entries); return; }
    for (unsigned long i = 0; i < n; i++) {
        id e = ((msg_id_ulong)objc_msgSend)(entries, g_selObjAt, i);
        if (should_write(e))
            ((msg_void_id)objc_msgSend)(filtered, g_selAdd, e);
    }
    g_origWriteArray(self, _cmd, filtered);
}

// ---------------------------------------------------------------------------
static IMP install_method(Class cls, const char *name, IMP replacement, const char *types) {
    if (!cls) return NULL;
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    return class_replaceMethod(cls, sel, replacement, types);
}

%ctor {
    if (access(kFlagAll, F_OK) == 0 || access(kFlagOff, F_OK) == 0)
        g_passthrough = 1;

    g_selEntryKey     = sel_registerName("entryKey");
    g_selUTF8         = sel_registerName("UTF8String");
    g_selCount        = sel_registerName("count");
    g_selObjAt        = sel_registerName("objectAtIndex:");
    g_selAdd          = sel_registerName("addObject:");
    g_selArray        = sel_registerName("array");
    g_clsMutableArray = objc_getClass("NSMutableArray");

    Class sql = objc_getClass("PLSQLiteConnection");
    g_origWriteEntry = (orig_single_fn)install_method(sql, "writeEntry:",
                           (IMP)hook_writeEntry, "q24@0:8@16");
    g_origWriteArray = (orig_void_id_fn)install_method(sql, "writeArrayEntries:",
                           (IMP)hook_writeArrayEntries, "v24@0:8@16");

    // Fail-open: if the single-entry gate could not be installed, do not drop
    // anything (the array hook alone would be an incomplete filter).
    if (!g_origWriteEntry) g_passthrough = 1;
}
