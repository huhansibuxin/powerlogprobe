// PowerlogProbe v0.9.0 - DIAGNOSTIC build for com.apple.aggregated (iOS 16 / 20G81)
// =============================================================================
// PURPOSE
//   Read-only instrumentation that answers three questions before we implement
//   plan A (short-circuit every non-battery event at the PowerlogCore dispatch
//   entry, while keeping "Settings > Battery > per-App usage" alive):
//     1. Can a tweak actually load inside aggregated? (Choicy / jetsam / sandbox)
//     2. What PL* ObjC classes and methods exist at runtime? -> find the single
//        event dispatch entry we will hook in plan A.
//     3. Which CurrentPowerlog.PLSQL tables actually grow over a 120s window?
//        -> derive the real blacklist / whitelist instead of guessing.
//
//   THIS BUILD DOES NOT HOOK, SWIZZLE, SHORT-CIRCUIT OR SKIP ANYTHING.
//   It only reads. Settings > Battery must behave exactly as before.
//
// HARD CONSTRAINTS (copied from KeybagCacheSkip / LocalStorageSkip)
//   - ZERO substrate/ellekit LINK dependency: if aggregated cannot dlopen
//     libellekit, any LC_LOAD_DYLIB referencing it makes the tweak fail to load
//     silently. -Wl,-dead_strip_dylibs + a CI assertion enforce this.
//   - NO UIKit, NO Foundation, NO PreferenceLoader, NO settings bundle.
//     aggregated is a small launchd daemon; do not drag heavyweight frameworks
//     into it. Only libSystem/libobjc/libsqlite3, all already resident.
//   - NO polling / heartbeat. One dispatch_after_f (one-shot, not a timer).
//   - All logging via open(2)/write(2), no NSLog/os_log (logd is disabled on
//     this device), no buffered stdio that could be lost on daemon exit.
//   - max(rowid) instead of count(*) for snapshots: O(log n) B-tree rightmost
//     page lookup, so 459 tables cost milliseconds and do NOT create a fake
//     99% CPU spike in the resident htop watcher.
// =============================================================================

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#include <sqlite3.h>
#include <glob.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000ull
#endif

static const char *kLogCandidates[] = {
    "/var/mobile/Documents/PowerlogProbe/probe.log",
    "/var/mobile/Library/Logs/PowerlogProbe.log",
    "/var/tmp/PowerlogProbe.log",
};
static const char *kLogDirs[] = {
    "/var/mobile/Documents/PowerlogProbe",
    "/var/mobile/Library/Logs",
    "/var/tmp",
};

// Device-specific SystemGroup GUID of this test phone. glob() below is the
// portable fallback for other devices.
static const char *kDbPath =
    "/var/containers/Shared/SystemGroup/006508CA-DFD9-4B52-B841-1880C958EDC3"
    "/Library/BatteryLife/CurrentPowerlog.PLSQL";
static const char *kDbGlob =
    "/var/containers/Shared/SystemGroup/*/Library/BatteryLife/CurrentPowerlog.PLSQL";

static int g_fd = -1;
static const char *g_logpath = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void plog(const char *fmt, ...) {
    if (g_fd < 0) return;
    char body[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(body) - 1) n = (int)sizeof(body) - 1;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%F %T", &tm);

    char line[4200];
    int m = snprintf(line, sizeof(line), "[%s] %.*s\n", ts, n, body);
    if (m <= 0) return;
    if (m > (int)sizeof(line) - 1) m = (int)sizeof(line) - 1;
    pthread_mutex_lock(&g_lock);
    (void)write(g_fd, line, (size_t)m);
    pthread_mutex_unlock(&g_lock);
}

static void open_log(void) {
    for (size_t i = 0; i < sizeof(kLogCandidates) / sizeof(kLogCandidates[0]); i++) {
        (void)mkdir(kLogDirs[i], 0755);
        int fd = open(kLogCandidates[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            g_fd = fd;
            g_logpath = kLogCandidates[i];
            return;
        }
    }
}

// --- 1. loaded images -------------------------------------------------------
static void dump_images(void) {
    uint32_t n = _dyld_image_count();
    plog("=== IMAGES %u ===", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        const struct mach_header *h = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!nm) continue;
        const char *tag = "";
        if (h && h->filetype == MH_EXECUTE) tag = "MAIN";
        else if (strstr(nm, "Powerlog")) tag = "POWERLOG";
        else if (strstr(nm, "AggregateDictionary")) tag = "AD";
        else if (strstr(nm, "ellekit") || strstr(nm, "substrate")) tag = "INJECTOR";
        else if (strstr(nm, "PowerlogProbe")) tag = "SELF";
        else if (strstr(nm, "libsqlite3")) tag = "SQLITE";
        plog("IMG %-9s %3u base=%p slide=%#lx %s", tag, i, (void *)h, (long)slide, nm);
    }
}

// --- 2. PowerlogCore ObjC surface -------------------------------------------
static int is_pl_class(const char *n) {
    if (!n) return 0;
    if (strncmp(n, "PL", 2) == 0) return 1;
    if (strstr(n, "Powerlog") || strstr(n, "AggregateDictionary")) return 1;
    if (strstr(n, "Battery") || strstr(n, "Energy") || strstr(n, "Accounting")) return 1;
    return 0;
}

static void dump_methods(Class cls, const char *cn, int is_class_methods) {
    unsigned int mc = 0;
    Method *ms = class_copyMethodList(cls, &mc);
    if (!ms) return;
    unsigned int cap = is_class_methods ? 60u : 120u;
    unsigned int lim = mc < cap ? mc : cap;
    for (unsigned int j = 0; j < lim; j++) {
        SEL s = method_getName(ms[j]);
        const char *sn = s ? sel_getName(s) : "?";
        const char *ty = method_getTypeEncoding(ms[j]);
        IMP imp = method_getImplementation(ms[j]);
        plog("  %c[%s %s] imp=%p enc=%s", is_class_methods ? '+' : '-',
             cn, sn ? sn : "?", (void *)(uintptr_t)imp, ty ? ty : "");
    }
    if (mc > lim) plog("  ... %u more methods", mc - lim);
    free(ms);
}

static void dump_classes(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) { plog("=== CLASSES 0 ==="); return; }
    Class *cs = (Class *)malloc(sizeof(Class) * (size_t)(n + 1));
    if (!cs) return;
    n = objc_getClassList(cs, n);
    plog("=== CLASSES total=%d ===", n);
    int hit = 0;
    for (int i = 0; i < n; i++) {
        const char *cn = class_getName(cs[i]);
        if (!is_pl_class(cn)) continue;
        hit++;
        plog("CLASS %s", cn);
        dump_methods(cs[i], cn, 0);
        Class meta = object_getClass((id)cs[i]);
        if (meta && meta != cs[i]) dump_methods(meta, cn, 1);
    }
    plog("=== CLASSES matched=%d ===", hit);
    free(cs);
}

// --- 3. table growth snapshots ---------------------------------------------
static const char *find_db(void) {
    if (access(kDbPath, R_OK) == 0) return kDbPath;
    glob_t g;
    memset(&g, 0, sizeof(g));
    if (glob(kDbGlob, 0, NULL, &g) != 0 || g.gl_pathc == 0) {
        globfree(&g);
        return NULL;
    }
    char *p = strdup(g.gl_pathv[0]);
    globfree(&g);
    return p;  // NULL on OOM; caller checks
}

static void snapshot(const char *tag) {
    const char *path = find_db();
    if (!path) { plog("SNAP %s DB_NOT_FOUND", tag); return; }
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        plog("SNAP %s OPEN_FAIL %s", tag, db ? sqlite3_errmsg(db) : "oom");
        if (db) sqlite3_close(db);
        return;
    }
    plog("SNAP_BEGIN %s db=%s", tag, path);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            -1, &st, NULL) == SQLITE_OK) {
        char (*names)[160] = NULL;
        int cap = 0, cnt = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *s = sqlite3_column_text(st, 0);
            if (!s) continue;
            if (cnt == cap) {
                int ncap = cap ? cap * 2 : 256;
                char (*tmp)[160] = (char (*)[160])realloc(names, (size_t)ncap * 160);
                if (!tmp) break;
                names = tmp;
                cap = ncap;
            }
            snprintf(names[cnt], 160, "%s", (const char *)s);
            cnt++;
        }
        sqlite3_finalize(st);
        st = NULL;

        for (int i = 0; i < cnt; i++) {
            char sql[320];
            long long v = -1;
            snprintf(sql, sizeof(sql), "SELECT max(rowid) FROM \"%s\"", names[i]);
            if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                sqlite3_step(st) == SQLITE_ROW) {
                v = sqlite3_column_int64(st, 0);
                sqlite3_finalize(st);
                st = NULL;
            } else {
                if (st) { sqlite3_finalize(st); st = NULL; }
                // WITHOUT ROWID table: fall back to a full count.
                snprintf(sql, sizeof(sql), "SELECT count(*) FROM \"%s\"", names[i]);
                if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                    sqlite3_step(st) == SQLITE_ROW) {
                    v = sqlite3_column_int64(st, 0);
                }
                if (st) { sqlite3_finalize(st); st = NULL; }
            }
            plog("T %s %s %lld", tag, names[i], v);
        }
        free(names);
    }
    plog("SNAP_END %s", tag);
    sqlite3_close(db);
}

static void delayed_snapshot(void *unused) {
    (void)unused;
    snapshot("T120");
    plog("=== DIAG END ===");
}

%ctor {
    open_log();
    plog("=== PowerlogProbe 0.9.0 DIAG START pid=%d ===", getpid());
    plog("LOGPATH %s", g_logpath ? g_logpath : "NONE (all candidates failed)");
    dump_images();
    dump_classes();
    snapshot("T0");
    // One-shot, 120s later. Not a timer, not a polling loop.
    dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(120 * NSEC_PER_SEC)),
                     dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
                     NULL, delayed_snapshot);
}
