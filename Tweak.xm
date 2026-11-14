// PowerlogProbe v1.2.0 - PLAN C3 (standalone blacklist build)
// =============================================================================
// WHY THIS BUILD EXISTS
//   PLAN A (whitelist) and PLAN B (SQL_ONLY whitelist) both made
//   "Settings > Battery" per-App ENERGY percentages inaccurate. On-device DB
//   comparison (2026-11-14 18:26) and planB.log (19:10-20:35) proved why:
//     - 97 of the 129 BLOCKed keys were hardware/state Agents (XPC 18,
//       IOReport 13, Display 11, BT 7, Audio 6, BB 6, Wifi 6 ...). Those
//       EventForward_* events are the inputs PLAccountingQualificationManager
//       uses to decide WHICH APP owns WHICH energy node.
//     - EnergyEstimateEvents (raw energy) was never blocked, but
//       QualificationEvents fell 696 -> 157 rows/hour and
//       Aggregate_QualificationEnergy went 11 -> 0 => total energy present,
//       distribution ratio wrong => percentages look wrong.
//   Also proven: the 99% CPU bursts are NOT the hourly aggregate rollup.
//   They are a 3-second batch flush of raw energy rows (606 rows at
//   16:55:19-16:55:22). The aggregate tables are written at the top of the
//   hour with no CPU spike. Blocking the flush only makes the data worse.
//
// PLAN C3 POLICY (default, NO flag file needed)
//   1. BLACKLIST, not whitelist: only explicitly useless/high-volume
//      diagnostic tables are dropped. EVERYTHING else passes.
//   2. Hardware/state Agents are ALLOWED. Only pure diagnostic telemetry is
//      denied. This keeps the per-App energy attribution inputs intact.
//   3. Hook ONLY the SQL layer (PLSQLiteConnection writeEntry: and
//      writeArrayEntries:). PLCoreStorage is left completely untouched, so
//      rowids, completion blocks, qualification state machine and hourly
//      aggregates run 100% stock. Only the final INSERT is skipped.
//   4. Short-circuited writes return a synthetic non-zero rowid
//      (0x4000000000000000+) so callers still see "write succeeded".
//      setWriteToDB: is NEVER called (that dirtied entries in PLAN A).
//
// OPTIONAL CONTROL FLAGS (empty files, read once in ctor, kickstart to apply)
//   MODE_C3_STRICT     use PLAN B's original 33-prefix deny list (A-B control)
//   MODE_SQL_ONLY      PLAN B default behaviour (whitelist at SQL layer)
//   MODE_WIDE          PLAN B wide whitelist (CS + SQL hooks)
//   MODE_ORIGINAL      bit-for-bit PLAN A replay
//   MODE_BLACKLIST     explicit C3 (same as the default)
//   PASSTHROUGH_ALL / DISABLED : hooks installed but completely inert
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
#define kLogPath  "/var/mobile/Documents/PowerlogProbe/planC3.log"
#define kFlagAll  "/var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL"
#define kFlagOff  "/var/mobile/Documents/PowerlogProbe/DISABLED"
#define kFlagWide "/var/mobile/Documents/PowerlogProbe/MODE_WIDE"
#define kFlagBlack "/var/mobile/Documents/PowerlogProbe/MODE_BLACKLIST"
#define kFlagOrig "/var/mobile/Documents/PowerlogProbe/MODE_ORIGINAL"
#define kFlagSql  "/var/mobile/Documents/PowerlogProbe/MODE_SQL_ONLY"
#define kFlagStrict "/var/mobile/Documents/PowerlogProbe/MODE_C3_STRICT"

// Build tag, kept alive for the CI strings assertion. Never read at runtime.
static const char kBuildTag[] __attribute__((used)) =
    "PowerlogProbe 1.2.0 PLAN C3 START standalone blacklist";

typedef enum {
    MODE_SQL_ONLY  = 0,
    MODE_WIDE      = 1,
    MODE_BLACKLIST = 2,   // PLAN C3 default
    MODE_ORIGINAL  = 3    // v1.0.0 PLAN A replay
} Mode;

static Mode g_mode = MODE_BLACKLIST;
static int  g_passthrough = 0;
static int  g_strict = 0;   // 1 -> use PLAN B's original deny list

// ---------------------------------------------------------------------------
// PLAN A whitelist (kept for MODE_SQL_ONLY / MODE_WIDE / MODE_ORIGINAL)
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
static const char *kWideExclude[] = {
    "PLPowerAssertionAgent_EventForward_Assertion",
};

// ---------------------------------------------------------------------------
// PLAN C3 deny list (default): pure diagnostic / high-volume telemetry ONLY.
// Deliberately ABSENT: PLWifiAgent_, PLBBAgent_, PLDisplayAgent_,
// PLAudioAgent_, PLXPCAgent_, PLXPCService_, PLBluetoothAgent_,
// PLNetworkAgent_, PLVideoAgent_ - these are the per-App energy attribution
// inputs. Blocking them made the battery percentages inaccurate in PLAN A/B.
// ---------------------------------------------------------------------------
static const char *kDenyClean[] = {
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

// PLAN B's original 33-prefix list, used only with MODE_C3_STRICT (A-B control)
static const char *kDenyFull[] = {
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
    if (strstr(k, "_EventForward_") || strstr(k, "_EventInterval_")) return 1;
    return 0;
}

static int blacklist_hit(const char *k) {
    if (!k || !*k) return 0;
    const char * const *list = g_strict ? kDenyFull : kDenyClean;
    size_t n = g_strict ? (sizeof(kDenyFull) / sizeof(kDenyFull[0]))
                        : (sizeof(kDenyClean) / sizeof(kDenyClean[0]));
    for (size_t i = 0; i < n; i++)
        if (strncmp(k, list[i], strlen(list[i])) == 0) return 1;
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
// WIDE / ORIGINAL only. PLAN C3 never installs this.
// ---------------------------------------------------------------------------
static orig_single_fn g_origCS = NULL;
static long long hook_cs_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_cs_pass, &g_cs_block))
        return g_origCS ? g_origCS(self, _cmd, entry) : 0;
    return short_circuit_value(entry);
}

// ---------------------------------------------------------------------------
// Hook 2: -[PLCoreStorage writeEntries:withCompletionBlock:] (v32@0:8@16@?24)
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
// PLAN C3 / SQL_ONLY: the ONLY single-entry filter point.
// ---------------------------------------------------------------------------
static orig_single_fn g_origSQL = NULL;
static long long hook_sql_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_sql_pass, &g_sql_block))
        return g_origSQL ? g_origSQL(self, _cmd, entry) : 0;
    return short_circuit_value(entry);
}

// ---------------------------------------------------------------------------
// Hook 4: -[PLSQLiteConnection writeArrayEntries:]  (v24@0:8@16)
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

    const char *modeName = "BLACKLIST(C3)";
    switch (g_mode) {
        case MODE_SQL_ONLY:  modeName = "SQL_ONLY"; break;
        case MODE_WIDE:      modeName = "WIDE"; break;
        case MODE_ORIGINAL:  modeName = "ORIGINAL(PLAN A replay)"; break;
        default: break;
    }
    plog("=== PowerlogProbe 1.2.0 PLAN C3 START pid=%d mode=%s list=%s layer=%s passthrough=%d ===",
         getpid(), modeName, g_strict ? "STRICT(PLAN B 33)" : "CLEAN",
         (g_mode == MODE_SQL_ONLY || g_mode == MODE_BLACKLIST) ? "SQL_ONLY" : "CS+SQL",
         g_passthrough);

    if (g_mode == MODE_SQL_ONLY || g_mode == MODE_BLACKLIST) {
        // PLAN C3: leave PLCoreStorage untouched so rowids, completion blocks,
        // the qualification state machine and hourly aggregates all run stock.
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
    plog("=== PLAN C3 READY mode=%s list=%s ===", modeName, g_strict ? "STRICT" : "CLEAN");
}

%ctor {
    (void)mkdir(kDir, 0755);
    g_fd = open(kLogPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) {
        // Fail-open: never run an unobservable experiment on a system daemon.
        g_passthrough = 1;
    }
    // Default is PLAN C3 (BLACKLIST + CLEAN list + SQL-only layer).
    if (access(kFlagSql, F_OK) == 0)     g_mode = MODE_SQL_ONLY;
    if (access(kFlagWide, F_OK) == 0)    g_mode = MODE_WIDE;
    if (access(kFlagBlack, F_OK) == 0)   g_mode = MODE_BLACKLIST;
    if (access(kFlagOrig, F_OK) == 0)    g_mode = MODE_ORIGINAL;
    if (access(kFlagStrict, F_OK) == 0)  g_strict = 1;
    if (access(kFlagAll, F_OK) == 0 || access(kFlagOff, F_OK) == 0) g_passthrough = 1;
    install();
}
