// PowerlogProbe v1.1.0 - PLAN B (multi-mode A/B/C test build)
// =============================================================================
// WHY THIS BUILD EXISTS
//   v1.0.0 PLAN A killed CPU spikes but broke "Settings > Battery" per-App
//   ENERGY percentages (app runtimes still showed). On-device DB comparison
//   (2026-11-14 18:26) proved the energy ledger was NEVER blocked:
//     EnergyEstimateEvents      1800 -> 2731 rows (still written, non-zero)
//     Application                649 ->  491 rows (runtime chain OK)
//     QualificationEvents        696 ->  157 rows (-77%  <== broken)
//     Aggregate_QualificationEnergy 11 -> 0 rows (per-App energy gone)
//   Root cause is HOW we short-circuited, not WHICH key was missing:
//     -[PLCoreStorage writeEntry:] returns a rowid; returning 0 looks like a
//     failed write to PLAccountingQualificationManager's in-memory state
//     machine (addEnergyEstimate: / didQualifyEnergyEvent: / close...).
//     -[PLEntry setWriteToDB:NO] dirties the entry object.
//     Blocking every hardware Agent's EventForward_* removed the inputs that
//     decide "which app owns which node right now".
//
// FOUR MODES, ONE INSTALL (flag file + kickstart -k to switch, no rebuild)
//   (no flag)        MODE SQL_ONLY     [recommended, default]
//                    Do NOT touch PLCoreStorage at all. Filter only at the
//                    lowest layer: -[PLSQLiteConnection writeEntry:] and
//                    -writeArrayEntries:. All rowids, completion blocks,
//                    qualification state machine and hourly aggregates run
//                    100% unmodified; only the final INSERT is skipped.
//   MODE_WIDE        Three hooks like PLAN A, but the whitelist additionally
//                    allows every low-frequency EventForward_/EventInterval_
//                    key (the qualification inputs). High-frequency
//                    EventBackward_/EventPoint_ telemetry stays blocked.
//   MODE_BLACKLIST   Three hooks, inverse policy: block only explicitly listed
//                    useless/high-volume tables, pass everything else.
//   MODE_ORIGINAL    Bit-for-bit PLAN A behaviour (return 0 + setWriteToDB:NO
//                    + narrow whitelist). A-B-A control to reproduce the bug.
//   PASSTHROUGH_ALL / DISABLED : hooks installed but completely inert.
//
// ALL non-ORIGINAL modes return a synthetic non-zero rowid instead of 0, so
// callers see "write succeeded" and keep their downstream logic intact.
// The synthetic IDs start at 0x4000000000000000 - far above any real rowid.
//
// HARD CONSTRAINTS
//   - ZERO substrate/ellekit LINK dependency: no Logos hooking directives,
//     no MSHookFunction. Pure objc/runtime class_replaceMethod + %ctor.
//   - NO Foundation / UIKit link; NSString/NSArray/NSMutableArray reached
//     through objc_msgSend only.
//   - NO polling / timer. Logging is event-count driven (<=1 line / 500 calls).
// =============================================================================

#import <objc/runtime.h>
#import <objc/message.h>
#import <stdarg.h>
#import <stdint.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>
#import <fcntl.h>
#import <unistd.h>
#import <pthread.h>
#import <sys/stat.h>

#define kDir      "/var/mobile/Documents/PowerlogProbe"
#define kLogPath  "/var/mobile/Documents/PowerlogProbe/planB.log"
#define kFlagAll  "/var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL"
#define kFlagOff  "/var/mobile/Documents/PowerlogProbe/DISABLED"
#define kFlagWide "/var/mobile/Documents/PowerlogProbe/MODE_WIDE"
#define kFlagBlack "/var/mobile/Documents/PowerlogProbe/MODE_BLACKLIST"
#define kFlagOrig "/var/mobile/Documents/PowerlogProbe/MODE_ORIGINAL"

// Build tag, kept alive for the CI strings assertion. Never read at runtime.
static const char kBuildTag[] __attribute__((used)) =
    "PowerlogProbe 1.1.0 PLAN B START multi-mode";

typedef enum {
    MODE_SQL_ONLY  = 0,   // default, recommended
    MODE_WIDE      = 1,
    MODE_BLACKLIST = 2,
    MODE_ORIGINAL  = 3    // v1.0.0 PLAN A replay
} Mode;

static Mode g_mode = MODE_SQL_ONLY;
static int  g_passthrough = 0;

// ---------------------------------------------------------------------------
// PLAN A whitelist (unchanged): only what Settings > Battery needs.
// ---------------------------------------------------------------------------
static const char *kAllowPrefix[] = {
    "PLAccountingOperator_",
    "PLApplicationAgent_",
    "PLProcessMonitorAgent_EventForward_ProcessID",
    "PLScreenStateAgent_EventForward_ScreenState",
    "PLBatteryAgent_EventBackward_Battery",
    "PLStorageOperator_EventForward_TimeOffset",
    "BatteryMetrics_",
};
static const char *kAllowSub[] = {
    "_Aggregate_",
    "EnergyEstimate",
    "RootNodeEnergy",
    "Energy",
    "Battery",
};

// MODE_WIDE: qualification inputs. These are LOW volume in the 120s growth
// snapshot (mostly 1-2 rows), so allowing them costs almost nothing.
static const char *kWideExclude[] = {
    "PLPowerAssertionAgent_EventForward_Assertion", // 67 rows/120s, keep blocked
};

// MODE_BLACKLIST: only these are dropped. Everything else (including every
// PLAccountingOperator_*, PLApplicationAgent_*, PLBatteryAgent_* and all
// Aggregate tables) flows through untouched.
static const char *kDenyPrefix[] = {
    "PLIOReportAgent_",
    "PLCoalitionAgent_",
    "PLXPCAgent_",
    "PLXPCService_",
    "PLBBAgent_",
    "PLWifiAgent_",
    "PLBluetoothAgent_",
    "PLDisplayAgent_",
    "PLSMCAgent_",
    "PLConfigAgent_",
    "PLLocaleAgent_",
    "PLSpringBoardAgent_",
    "PLPowerAssertionAgent_",
    "PLRenderingAgent_",
    "PLNetworkAgent_",
    "PLEduAgent_",
    "PLPerformanceAgent_",
    "PLProcessMonitorAgent_EventPoint_",
    "PLProcessMonitorAgent_EventBackward_",
    "PLAudioAgent_",
    "PLVideoAgent_",
    "PLProximityAgent_",
    "PLMDNSAgent_",
    "PLSiriAgent_",
    "PLIdentityServicesAgent_",
    "PLPushAgent_",
    "PLCoreDuetAgent_",
    "PLSCDynamicStoreAgent_",
    "PLButtonAgent_",
    "PPT",
    "ConfigMetrics_",
    "LocaleMetrics_",
    "WifiMetrics_",
    "DisplayMetrics_",
};

// ---------------------------------------------------------------------------
// Lightweight event log (open/write only; os_log is dead on this device)
// ---------------------------------------------------------------------------
static int g_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_seen[1024];
static unsigned long long g_calls = 0;
static unsigned long long g_fake = 0;
static unsigned long long g_unknown = 0;
static unsigned long long g_cs_pass = 0, g_cs_block = 0;
static unsigned long long g_bat_pass = 0, g_bat_block = 0;
static unsigned long long g_sql_pass = 0, g_sql_block = 0;
static unsigned long long g_arr_pass = 0, g_arr_block = 0;

static void plog(const char *fmt, ...) {
    if (g_fd < 0) return;
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(body) - 1) n = (int)sizeof(body) - 1;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%F %T", &tmv);
    char line[1152];
    int m = snprintf(line, sizeof(line), "[%s] %.*s\n", ts, n, body);
    if (m <= 0) return;
    if (m > (int)sizeof(line) - 1) m = (int)sizeof(line) - 1;
    pthread_mutex_lock(&g_lock);
    (void)write(g_fd, line, (size_t)m);
    pthread_mutex_unlock(&g_lock);
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

static void log_key_once(const char *verdict, const char *key) {
    uint32_t h = fnv1a(key) ^ (fnv1a(verdict) << 7);
    uint32_t slot = h & 1023u;
    for (uint32_t i = 0; i < 8; i++) {
        uint32_t *p = &g_seen[(slot + i) & 1023u];
        if (*p == h) return;
        if (*p == 0) {
            pthread_mutex_lock(&g_lock);
            if (*p == 0) { *p = h; pthread_mutex_unlock(&g_lock); plog("KEY %s %s", verdict, key); return; }
            pthread_mutex_unlock(&g_lock);
        }
    }
}

static void maybe_stat(void) {
    if ((__sync_add_and_fetch(&g_calls, 1) % 500ULL) != 0ULL) return;
    plog("STAT cs=%llu/%llu batch=%llu/%llu sql=%llu/%llu arr=%llu/%llu unknown=%llu",
         g_cs_pass, g_cs_block, g_bat_pass, g_bat_block,
         g_sql_pass, g_sql_block, g_arr_pass, g_arr_block, g_unknown);
}

// A legal-looking, never-colliding rowid: callers keep their downstream logic.
static long long fake_rowid(void) {
    return (long long)(0x4000000000000000ULL + __sync_add_and_fetch(&g_fake, 1));
}

// ---------------------------------------------------------------------------
// objc_msgSend shims (zero Foundation link)
// ---------------------------------------------------------------------------
typedef id           (*msg_id)(id, SEL);
typedef const char * (*msg_cstr)(id, SEL);
typedef unsigned long(*msg_ulong)(id, SEL);
typedef id           (*msg_id_ulong)(id, SEL, unsigned long);
typedef void         (*msg_void_id)(id, SEL, id);
typedef void         (*msg_void_bool)(id, SEL, char);
typedef long long    (*orig_single_fn)(id, SEL, id);
typedef void         (*orig_void_id_fn)(id, SEL, id);
typedef void         (*orig_batch_fn)(id, SEL, id, id);

static SEL g_selEntryKey, g_selUTF8, g_selCount, g_selObjAt, g_selAdd, g_selArray;
static SEL g_selSetWriteToDB;
static Class g_clsMutableArray;

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

static int whitelisted_orig(const char *k) {
    if (!k || !*k) return 0;
    for (size_t i = 0; i < sizeof(kAllowPrefix) / sizeof(kAllowPrefix[0]); i++)
        if (strncmp(k, kAllowPrefix[i], strlen(kAllowPrefix[i])) == 0) return 1;
    for (size_t i = 0; i < sizeof(kAllowSub) / sizeof(kAllowSub[0]); i++)
        if (strstr(k, kAllowSub[i]) != NULL) return 1;
    return 0;
}

static int whitelisted_wide(const char *k) {
    if (whitelisted_orig(k)) return 1;
    for (size_t i = 0; i < sizeof(kWideExclude) / sizeof(kWideExclude[0]); i++)
        if (strncmp(k, kWideExclude[i], strlen(kWideExclude[i])) == 0) return 0;
    // Qualification inputs: low-volume forward/interval agent events.
    if (strstr(k, "_EventForward_") || strstr(k, "_EventInterval_")) return 1;
    return 0;
}

static int blacklist_hit(const char *k) {
    if (!k || !*k) return 0;
    for (size_t i = 0; i < sizeof(kDenyPrefix) / sizeof(kDenyPrefix[0]); i++)
        if (strncmp(k, kDenyPrefix[i], strlen(kDenyPrefix[i])) == 0) return 1;
    return 0;
}

static int allowed(const char *k) {
    switch (g_mode) {
        case MODE_BLACKLIST: return blacklist_hit(k) ? 0 : 1;
        case MODE_WIDE:      return whitelisted_wide(k);
        case MODE_ORIGINAL:  return whitelisted_orig(k);
        default:             return whitelisted_orig(k);  // MODE_SQL_ONLY
    }
}

// 1 = allow the write (or at least let the caller believe it succeeded).
static int verdict(id entry, unsigned long long *pass, unsigned long long *block) {
    if (g_passthrough || !entry) { __sync_add_and_fetch(pass, 1); return 1; }
    const char *k = entry_key(entry);
    if (!k) { __sync_add_and_fetch(&g_unknown, 1); __sync_add_and_fetch(pass, 1); return 1; }
    int allow = allowed(k);
    if (allow) __sync_add_and_fetch(pass, 1);
    else       __sync_add_and_fetch(block, 1);
    log_key_once(allow ? "PASS" : "BLOCK", k);
    maybe_stat();
    return allow;
}

// ONLY used by MODE_ORIGINAL to faithfully replay PLAN A's side effects.
static void mark_no_write(id entry) {
    if (!entry) return;
    Class c = object_getClass(entry);
    if (c && class_respondsToSelector(c, g_selSetWriteToDB))
        ((msg_void_bool)objc_msgSend)(entry, g_selSetWriteToDB, (char)0);
}

static long long short_circuit_value(id entry) {
    if (g_mode == MODE_ORIGINAL) { mark_no_write(entry); return 0; }
    return fake_rowid();
}

// ---------------------------------------------------------------------------
// Hook 1: -[PLCoreStorage writeEntry:]  (q24@0:8@16)
// ---------------------------------------------------------------------------
static orig_single_fn g_origCS = NULL;
static long long hook_cs_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_cs_pass, &g_cs_block))
        return g_origCS ? g_origCS(self, _cmd, entry) : 0;
    return short_circuit_value(entry);
}

// ---------------------------------------------------------------------------
// Hook 2: -[PLCoreStorage writeEntries:withCompletionBlock:] (v32@0:8@16@?24)
// Always call the original (filtered) so completion blocks still fire.
// ---------------------------------------------------------------------------
static orig_batch_fn g_origBatch = NULL;
static void hook_cs_writeEntries(id self, SEL _cmd, id entries, id block) {
    if (!g_origBatch) return;
    if (g_passthrough || !entries ||
        !class_respondsToSelector(object_getClass(entries), g_selCount) ||
        !g_clsMutableArray) {
        g_origBatch(self, _cmd, entries, block);
        return;
    }
    unsigned long n = ((msg_ulong)objc_msgSend)(entries, g_selCount);
    id filtered = ((msg_id)objc_msgSend)((id)g_clsMutableArray, g_selArray);
    if (!filtered) { g_origBatch(self, _cmd, entries, block); return; }
    for (unsigned long i = 0; i < n; i++) {
        id e = ((msg_id_ulong)objc_msgSend)(entries, g_selObjAt, i);
        if (verdict(e, &g_bat_pass, &g_bat_block))
            ((msg_void_id)objc_msgSend)(filtered, g_selAdd, e);
        else if (g_mode == MODE_ORIGINAL)
            mark_no_write(e);
    }
    g_origBatch(self, _cmd, filtered, block);
}

// ---------------------------------------------------------------------------
// Hook 3: -[PLSQLiteConnection writeEntry:]  (q24@0:8@16)
// In MODE_SQL_ONLY this is the ONLY filter point.
// ---------------------------------------------------------------------------
static orig_single_fn g_origSQL = NULL;
static long long hook_sql_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_sql_pass, &g_sql_block))
        return g_origSQL ? g_origSQL(self, _cmd, entry) : 0;
    return short_circuit_value(entry);
}

// ---------------------------------------------------------------------------
// Hook 4: -[PLSQLiteConnection writeArrayEntries:]  (v24@0:8@16)
// Batch INSERT path; filter array, keep calling the original.
// ---------------------------------------------------------------------------
static orig_void_id_fn g_origSQLArray = NULL;
static void hook_sql_writeArrayEntries(id self, SEL _cmd, id entries) {
    if (!g_origSQLArray) return;
    if (g_passthrough || !entries ||
        !class_respondsToSelector(object_getClass(entries), g_selCount) ||
        !g_clsMutableArray) {
        g_origSQLArray(self, _cmd, entries);
        return;
    }
    unsigned long n = ((msg_ulong)objc_msgSend)(entries, g_selCount);
    id filtered = ((msg_id)objc_msgSend)((id)g_clsMutableArray, g_selArray);
    if (!filtered) { g_origSQLArray(self, _cmd, entries); return; }
    for (unsigned long i = 0; i < n; i++) {
        id e = ((msg_id_ulong)objc_msgSend)(entries, g_selObjAt, i);
        if (verdict(e, &g_arr_pass, &g_arr_block))
            ((msg_void_id)objc_msgSend)(filtered, g_selAdd, e);
        else if (g_mode == MODE_ORIGINAL)
            mark_no_write(e);
    }
    g_origSQLArray(self, _cmd, filtered);
}

// ---------------------------------------------------------------------------
static IMP install_method(Class cls, const char *name, IMP replacement, const char *types) {
    if (!cls) return NULL;
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    return class_replaceMethod(cls, sel, replacement, types);
}

static void install(void) {
    g_selEntryKey     = sel_registerName("entryKey");
    g_selUTF8         = sel_registerName("UTF8String");
    g_selCount        = sel_registerName("count");
    g_selObjAt        = sel_registerName("objectAtIndex:");
    g_selAdd          = sel_registerName("addObject:");
    g_selArray        = sel_registerName("array");
    g_selSetWriteToDB = sel_registerName("setWriteToDB:");
    g_clsMutableArray = objc_getClass("NSMutableArray");

    Class cs  = objc_getClass("PLCoreStorage");
    Class sql = objc_getClass("PLSQLiteConnection");

    const char *modeName = "SQL_ONLY";
    switch (g_mode) {
        case MODE_WIDE:      modeName = "WIDE"; break;
        case MODE_BLACKLIST: modeName = "BLACKLIST"; break;
        case MODE_ORIGINAL:  modeName = "ORIGINAL(PLAN A replay)"; break;
        default: break;
    }
    plog("=== PowerlogProbe 1.1.0 PLAN B START pid=%d mode=%s passthrough=%d ===",
         getpid(), modeName, g_passthrough);

    if (g_mode == MODE_SQL_ONLY) {
        // Deliberately leave PLCoreStorage untouched: rowids, completion
        // blocks, qualification state machine and hourly aggregates all run
        // exactly as stock. Only the final SQL INSERT is skipped.
        g_origSQL = (orig_single_fn)install_method(sql, "writeEntry:",
                        (IMP)hook_sql_writeEntry, "q24@0:8@16");
        g_origSQLArray = (orig_void_id_fn)install_method(sql, "writeArrayEntries:",
                        (IMP)hook_sql_writeArrayEntries, "v24@0:8@16");
        plog("HOOK SQL writeEntry: orig=%p %s", (void *)(uintptr_t)g_origSQL,
             g_origSQL ? "OK" : "FAILED");
        plog("HOOK SQL writeArrayEntries: orig=%p %s", (void *)(uintptr_t)g_origSQLArray,
             g_origSQLArray ? "OK" : "FAILED");
    } else {
        g_origCS = (orig_single_fn)install_method(cs, "writeEntry:",
                        (IMP)hook_cs_writeEntry, "q24@0:8@16");
        g_origBatch = (orig_batch_fn)install_method(cs, "writeEntries:withCompletionBlock:",
                        (IMP)hook_cs_writeEntries, "v32@0:8@16@?24");
        g_origSQL = (orig_single_fn)install_method(sql, "writeEntry:",
                        (IMP)hook_sql_writeEntry, "q24@0:8@16");
        plog("HOOK CS writeEntry: orig=%p %s", (void *)(uintptr_t)g_origCS,
             g_origCS ? "OK" : "FAILED");
        plog("HOOK CS writeEntries:withCompletionBlock: orig=%p %s",
             (void *)(uintptr_t)g_origBatch, g_origBatch ? "OK" : "FAILED");
        plog("HOOK SQL writeEntry: orig=%p %s", (void *)(uintptr_t)g_origSQL,
             g_origSQL ? "OK" : "FAILED");
    }
    plog("=== PLAN B READY mode=%s ===", modeName);
}

%ctor {
    (void)mkdir(kDir, 0755);
    g_fd = open(kLogPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) {
        // Fail-open: never run an unobservable experiment on a system daemon.
        g_passthrough = 1;
    }
    if (access(kFlagAll, F_OK) == 0 || access(kFlagOff, F_OK) == 0) g_passthrough = 1;
    if (access(kFlagWide, F_OK) == 0)  g_mode = MODE_WIDE;
    if (access(kFlagBlack, F_OK) == 0) g_mode = MODE_BLACKLIST;
    if (access(kFlagOrig, F_OK) == 0)  g_mode = MODE_ORIGINAL;
    install();
}
