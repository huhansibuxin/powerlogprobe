// PowerlogProbe v1.0.0 - PLAN A for com.apple.aggregated (iOS 16 / 20G81)
// =============================================================================
// GOAL
//   Keep ONLY "Settings > Battery > per-App battery usage" alive. Every other
//   Powerlog write (IOReport / baseband / wifi / bluetooth / assertions /
//   coalition memory / performance residency ...) is short-circuited BEFORE it
//   reaches SQLite, so the WAL/checkpoint/archiving batch that pins aggregated
//   at 99% CPU has nothing to chew on.
//
// WHY THIS IS SAFE-ISH (and why it is still an experiment)
//   * The battery breakdown is produced by PLBatteryBreakdownService reading
//     PLAccountingOperator_* energy tables + PLApplicationAgent_EventForward_
//     Application (foreground/background duration) + the battery level curve.
//     Those entryKeys are ALLOWED verbatim. Historical rows stay in the DB.
//   * We hook at PLCoreStorage (dispatch entry), not inside PLSQLiteConnection's
//     transaction, so no half-finished transaction / dangling statement.
//   * Batch path keeps calling the original implementation with a filtered
//     array, so completion blocks, caches and notifications still fire.
//   * A fallback hook on -[PLSQLiteConnection writeEntry:] catches the batch /
//     blocking paths that bypass -[PLCoreStorage writeEntry:].
//   * Any entry whose class does not respond to -entryKey is PASSED THROUGH
//     untouched (never crashed on an unknown payload).
//
// HARD CONSTRAINTS (proven on KeybagCacheSkip / diagnostic v0.9.0)
//   - ZERO substrate/ellekit LINK dependency: no Logos hooking directives,
//     no MSHookFunction. Pure objc/runtime method_setImplementation plus a
//     constructor. -dead_strip_dylibs and a CI assertion keep the dependency out.
//   - NO Foundation / UIKit / PreferenceLoader link. NSString, NSArray and
//     NSMutableArray are reached through objc_msgSend only.
//   - NO polling / heartbeat / timer. Logging is event-count driven.
//   - All logging via open(2)/write(2): os_log is dead on this device (logd is
//     permanently disabled). At most one line per distinct entryKey + one line
//     every 500 calls - the log itself must not create a new CPU spike.
//
// A/B SWITCHES (checked once at constructor time; kickstart -k aggregated)
//   touch /var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL  -> pass EVERYTHING
//   touch /var/mobile/Documents/PowerlogProbe/DISABLED          -> pass EVERYTHING
//   (both files absent -> whitelist filtering active)
//   SSH-side paths need the full /rootfs/private prefix.
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

#define kDir       "/var/mobile/Documents/PowerlogProbe"
#define kLogPath   "/var/mobile/Documents/PowerlogProbe/planA.log"
#define kFlagAll   "/var/mobile/Documents/PowerlogProbe/PASSTHROUGH_ALL"
#define kFlagOff   "/var/mobile/Documents/PowerlogProbe/DISABLED"

// ---------------------------------------------------------------------------
// Whitelist: ONLY what Settings > Battery needs.
// entryKey format (proven by the 120s table-growth snapshot):
//   <Operator>_Event<Type>_<Name>[_Array_xxx|_Aggregate_xxx|_Dynamic]
// ---------------------------------------------------------------------------
static const char *kAllowPrefix[] = {
    "PLAccountingOperator_",   // EnergyEstimateEvents / PowerEvents /
                               // QualificationEvents / DistributionEvents /
                               // RootNodeEnergy - the actual energy ledger
    "PLApplicationAgent_",     // foreground/background runtime per app
    "PLProcessMonitorAgent_EventForward_ProcessID", // pid -> bundle mapping
    "PLScreenStateAgent_EventForward_ScreenState",  // screen on/off timeline
    "PLBatteryAgent_EventBackward_Battery",         // battery level curve
    "PLStorageOperator_EventForward_TimeOffset",    // clock baseline, keep sane
    "BatteryMetrics_",                             // battery level aggregates
};
static const char *kAllowSub[] = {
    "_Aggregate_",             // every pre-aggregated rollup table
    "EnergyEstimate",
    "RootNodeEnergy",
    "Energy",                  // cheap insurance for breakdown queries
    "Battery",                 // cheap insurance for breakdown queries
};

static int g_passthrough = 0;
static int g_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long long g_cs_pass = 0, g_cs_block = 0;   // PLCoreStorage single
static unsigned long long g_bat_pass = 0, g_bat_block = 0; // PLCoreStorage batch
static unsigned long long g_sql_pass = 0, g_sql_block = 0; // PLSQLiteConnection
static unsigned long long g_unknown = 0;
static unsigned long long g_calls = 0;
static uint32_t g_seen[1024];                              // FNV hashes, one-shot logging

// ---------------------------------------------------------------------------
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

// Log a given (verdict, key) pair only once. O(1), no allocation, no timer.
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
    plog("STAT cs_single=%llu/%llu batch=%llu/%llu sql=%llu/%llu unknown=%llu",
         g_cs_pass, g_cs_block, g_bat_pass, g_bat_block,
         g_sql_pass, g_sql_block, g_unknown);
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
typedef void         (*orig_batch_fn)(id, SEL, id, id);

static SEL g_selEntryKey, g_selUTF8, g_selCount, g_selObjAt, g_selAdd, g_selArray;
static SEL g_selSetWriteToDB;
static Class g_clsMutableArray;

// entryKey -> C string. Returns NULL when the payload is not a PLEntry-like
// object; caller MUST pass such entries through untouched.
static const char *entry_key(id entry) {
    if (!entry) return NULL;
    Class c = object_getClass(entry);
    if (!c || !class_respondsToSelector(c, g_selEntryKey)) return NULL;
    id k = ((msg_id)objc_msgSend)(entry, g_selEntryKey);
    if (!k) return NULL;
    Class kc = object_getClass(k);
    if (!kc) return NULL;
    if (!class_respondsToSelector(kc, g_selUTF8)) {
        // PLEntryKey wrappers expose -entryKey returning the NSString.
        if (!class_respondsToSelector(kc, g_selEntryKey)) return NULL;
        k = ((msg_id)objc_msgSend)(k, g_selEntryKey);
        if (!k) return NULL;
        kc = object_getClass(k);
        if (!kc || !class_respondsToSelector(kc, g_selUTF8)) return NULL;
    }
    return ((msg_cstr)objc_msgSend)(k, g_selUTF8);
}

static int whitelisted(const char *k) {
    if (!k || !*k) return 0;
    for (size_t i = 0; i < sizeof(kAllowPrefix) / sizeof(kAllowPrefix[0]); i++)
        if (strncmp(k, kAllowPrefix[i], strlen(kAllowPrefix[i])) == 0) return 1;
    for (size_t i = 0; i < sizeof(kAllowSub) / sizeof(kAllowSub[0]); i++)
        if (strstr(k, kAllowSub[i]) != NULL) return 1;
    return 0;
}

// Returns 1 = allow, 0 = short-circuit. Never blocks an unknown payload.
static int verdict(id entry, unsigned long long *pass, unsigned long long *block) {
    if (g_passthrough || !entry) { __sync_add_and_fetch(pass, 1); return 1; }
    const char *k = entry_key(entry);
    if (!k) { __sync_add_and_fetch(&g_unknown, 1); __sync_add_and_fetch(pass, 1); return 1; }
    int allow = whitelisted(k);
    if (allow) __sync_add_and_fetch(pass, 1);
    else       __sync_add_and_fetch(block, 1);
    log_key_once(allow ? "PASS" : "BLOCK", k);
    maybe_stat();
    return allow;
}

// Mark the entry as "do not write" as well, in case a caller re-inspects it.
// Then short-circuit: no SQLite, no cache flush, no notification.
static void mark_no_write(id entry) {
    if (!entry) return;
    Class c = object_getClass(entry);
    if (c && class_respondsToSelector(c, g_selSetWriteToDB))
        ((msg_void_bool)objc_msgSend)(entry, g_selSetWriteToDB, (char)0);
}

// ---------------------------------------------------------------------------
// Hook 1: -[PLCoreStorage writeEntry:]  (q24@0:8@16)
// ---------------------------------------------------------------------------
static orig_single_fn g_origCS = NULL;
static long long hook_cs_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_cs_pass, &g_cs_block)) {
        return g_origCS ? g_origCS(self, _cmd, entry) : 0;
    }
    mark_no_write(entry);
    return 0;   // "not written" - a legal return value for a rowid-style API
}

// ---------------------------------------------------------------------------
// Hook 2: -[PLCoreStorage writeEntries:withCompletionBlock:]  (v32@0:8@16@?24)
// Filter the array, but ALWAYS call the original so completion blocks fire.
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
        else
            mark_no_write(e);
    }
    g_origBatch(self, _cmd, filtered, block);
}

// ---------------------------------------------------------------------------
// Hook 3: -[PLSQLiteConnection writeEntry:]  (q24@0:8@16)
// Fallback for batch / blocking / block-based paths that reach SQL directly.
// ---------------------------------------------------------------------------
static orig_single_fn g_origSQL = NULL;
static long long hook_sql_writeEntry(id self, SEL _cmd, id entry) {
    if (verdict(entry, &g_sql_pass, &g_sql_block)) {
        return g_origSQL ? g_origSQL(self, _cmd, entry) : 0;
    }
    mark_no_write(entry);
    return 0;
}

// ---------------------------------------------------------------------------
static orig_single_fn install_single(Class cls, const char *name, IMP replacement) {
    if (!cls) return NULL;
    SEL sel = sel_registerName(name);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    IMP old = class_replaceMethod(cls, sel, replacement, "q24@0:8@16");
    return (orig_single_fn)(void *)old;
}

static void install(void) {
    g_selEntryKey    = sel_registerName("entryKey");
    g_selUTF8        = sel_registerName("UTF8String");
    g_selCount       = sel_registerName("count");
    g_selObjAt       = sel_registerName("objectAtIndex:");
    g_selAdd         = sel_registerName("addObject:");
    g_selArray       = sel_registerName("array");
    g_selSetWriteToDB= sel_registerName("setWriteToDB:");
    g_clsMutableArray = objc_getClass("NSMutableArray");

    plog("=== PowerlogProbe 1.0.0 PLAN A START pid=%d ===", getpid());
    if (access(kFlagAll, F_OK) == 0) { g_passthrough = 1; plog("MODE PASSTHROUGH_ALL (flag file)"); }
    if (access(kFlagOff, F_OK) == 0) { g_passthrough = 1; plog("MODE DISABLED (flag file)"); }
    plog("MODE %s", g_passthrough ? "PASSTHROUGH (no filtering)" : "WHITELIST");
    plog("WHITELIST prefixes=%lu substrings=%lu",
         (unsigned long)(sizeof(kAllowPrefix) / sizeof(kAllowPrefix[0])),
         (unsigned long)(sizeof(kAllowSub) / sizeof(kAllowSub[0])));

    Class cs  = objc_getClass("PLCoreStorage");
    Class sql = objc_getClass("PLSQLiteConnection");
    plog("CLASS PLCoreStorage=%p PLSQLiteConnection=%p NSMutableArray=%p",
         (void *)cs, (void *)sql, (void *)g_clsMutableArray);

    g_origCS = install_single(cs, "writeEntry:", (IMP)hook_cs_writeEntry);
    plog("HOOK PLCoreStorage writeEntry: orig=%p %s",
         (void *)(uintptr_t)g_origCS, g_origCS ? "OK" : "FAILED");

    if (cs) {
        SEL sel = sel_registerName("writeEntries:withCompletionBlock:");
        Method m = class_getInstanceMethod(cs, sel);
        if (m) {
            IMP old = class_replaceMethod(cs, sel, (IMP)hook_cs_writeEntries, "v32@0:8@16@?24");
            g_origBatch = (orig_batch_fn)(void *)old;
        }
    }
    plog("HOOK PLCoreStorage writeEntries:withCompletionBlock: orig=%p %s",
         (void *)(uintptr_t)g_origBatch, g_origBatch ? "OK" : "FAILED");

    g_origSQL = install_single(sql, "writeEntry:", (IMP)hook_sql_writeEntry);
    plog("HOOK PLSQLiteConnection writeEntry: orig=%p %s",
         (void *)(uintptr_t)g_origSQL, g_origSQL ? "OK" : "FAILED");

    if (!g_origCS && !g_origBatch && !g_origSQL)
        plog("FATAL no hook installed - daemon left completely untouched");
    plog("=== PLAN A READY ===");
}

%ctor {
    (void)mkdir(kDir, 0755);
    g_fd = open(kLogPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0)
        g_fd = open("/var/tmp/PowerlogProbe_planA.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    // Fail-open: if we cannot log what we are filtering, filter nothing.
    if (g_fd >= 0) install();
}
