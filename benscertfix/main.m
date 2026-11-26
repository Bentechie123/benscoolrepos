// benscertfix - add up-to-date root certificates to an old iOS device (5-10).
//
// iOS keeps certificates the user has chosen to trust in the tsettings table of
// /private/var/Keychains/TrustStore.sqlite3 - the same place a root installed from
// a configuration profile goes. This tool adds the roots listed in roots.plist
// there, remembers which ones it added, and removes exactly those on uninstall.
//
//   benscertfix install   add missing roots (and drop ones a newer version removed)
//   benscertfix remove    remove every root this tool added
//   benscertfix status    show which roots are trusted

#import <Foundation/Foundation.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#define DB_DIR     "/private/var/Keychains"
#define DB_PATH    DB_DIR "/TrustStore.sqlite3"
#define ROOTS_PATH @"/Library/BensCertFix/roots.plist"
#define STATE_PATH @"/Library/BensCertFix/installed.plist"

// Trust settings for each row: an empty array, meaning "trust for everything".
static const char *kTrustSettings =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<array/>\n"
    "</plist>\n";

// Same schema securityd creates when the file doesn't exist yet.
static const char *kCreateSchema =
    "CREATE TABLE IF NOT EXISTS tsettings("
    "sha1 BLOB NOT NULL DEFAULT '',"
    "subj BLOB NOT NULL DEFAULT '',"
    "tset BLOB,"
    "data BLOB,"
    "PRIMARY KEY(sha1));"
    "CREATE INDEX IF NOT EXISTS isubj ON tsettings(subj);";

static void fail(NSString *msg, sqlite3 *db) {
    fprintf(stderr, "benscertfix: %s%s%s\n", msg.UTF8String,
            db ? ": " : "", db ? sqlite3_errmsg(db) : "");
    if (db) sqlite3_close(db);
    exit(1);
}

static NSString *hexString(NSData *data) {
    const unsigned char *b = data.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) [s appendFormat:@"%02X", b[i]];
    return s;
}

static sqlite3 *openStore(void) {
    BOOL existed = access(DB_PATH, F_OK) == 0;
    sqlite3 *db = NULL;
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) fail(@"can't open " @DB_PATH, db);
    sqlite3_busy_timeout(db, 10000); // securityd may be using it
    if (sqlite3_exec(db, kCreateSchema, NULL, NULL, NULL) != SQLITE_OK) fail(@"can't prepare trust table", db);
    if (!existed) {
        // Give the new file the same owner as the Keychains folder, like securityd would.
        struct stat dir;
        if (stat(DB_DIR, &dir) == 0) chown(DB_PATH, dir.st_uid, dir.st_gid);
        chmod(DB_PATH, 0644);
    }
    return db;
}

// Older iOS keys rows by sha1; a few builds use sha256. Match whatever this device has.
static NSString *hashColumn(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    NSString *column = @"sha1";
    if (sqlite3_prepare_v2(db, "SELECT sql FROM sqlite_master WHERE type='table' AND name='tsettings'", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        const char *sql = (const char *)sqlite3_column_text(st, 0);
        if (sql && strstr(sql, "sha256")) column = @"sha256";
    }
    sqlite3_finalize(st);
    return column;
}

static BOOL rowExists(sqlite3 *db, NSString *column, NSData *hash) {
    NSString *sql = [NSString stringWithFormat:@"SELECT COUNT(*) FROM tsettings WHERE %@=?", column];
    sqlite3_stmt *st = NULL;
    BOOL exists = NO;
    if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &st, NULL) != SQLITE_OK) fail(@"lookup failed", db);
    sqlite3_bind_blob(st, 1, hash.bytes, (int)hash.length, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) exists = sqlite3_column_int(st, 0) > 0;
    sqlite3_finalize(st);
    return exists;
}

static void deleteRow(sqlite3 *db, NSString *column, NSData *hash) {
    NSString *sql = [NSString stringWithFormat:@"DELETE FROM tsettings WHERE %@=?", column];
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &st, NULL) != SQLITE_OK) fail(@"delete failed", db);
    sqlite3_bind_blob(st, 1, hash.bytes, (int)hash.length, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) fail(@"delete failed", db);
    sqlite3_finalize(st);
}

static NSArray *loadRoots(void) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:ROOTS_PATH];
    NSArray *roots = plist[@"roots"];
    if (![roots isKindOfClass:[NSArray class]] || roots.count == 0) fail(@"can't read " ROOTS_PATH, NULL);
    return roots;
}

// Hex hashes (in the device's hash column) of rows this tool added.
static NSMutableSet *loadState(void) {
    NSArray *saved = [NSArray arrayWithContentsOfFile:STATE_PATH];
    return [NSMutableSet setWithArray:saved ?: @[]];
}

static void saveState(NSSet *state) {
    if (state.count == 0) {
        [[NSFileManager defaultManager] removeItemAtPath:STATE_PATH error:NULL];
    } else if (![[state.allObjects sortedArrayUsingSelector:@selector(compare:)] writeToFile:STATE_PATH atomically:YES]) {
        fail(@"can't save " STATE_PATH, NULL);
    }
}

static NSData *dataFromHex(NSString *hex) {
    NSMutableData *d = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        unsigned int byte = 0;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
        unsigned char c = (unsigned char)byte;
        [d appendBytes:&c length:1];
    }
    return d;
}

static int install(void) {
    NSArray *roots = loadRoots();
    sqlite3 *db = openStore();
    NSString *column = hashColumn(db);
    NSMutableSet *state = loadState();
    NSMutableSet *wanted = [NSMutableSet set];
    int added = 0, already = 0, dropped = 0;

    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) fail(@"store is busy", db);

    NSString *insertSQL = [NSString stringWithFormat:@"INSERT INTO tsettings (%@, subj, tset, data) VALUES (?, ?, ?, ?)", column];
    for (NSDictionary *root in roots) {
        NSData *hash = root[column];
        NSData *subj = root[@"subj"];
        NSData *der = root[@"data"];
        if (!hash || !subj || !der) fail([NSString stringWithFormat:@"bad entry %@", root[@"name"]], db);
        NSString *hex = hexString(hash);
        [wanted addObject:hex];

        if (rowExists(db, column, hash)) {
            if (![state containsObject:hex]) already++; // trusted before we came along
            continue;
        }
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, insertSQL.UTF8String, -1, &st, NULL) != SQLITE_OK) fail(@"insert failed", db);
        sqlite3_bind_blob(st, 1, hash.bytes, (int)hash.length, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, subj.bytes, (int)subj.length, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, kTrustSettings, (int)strlen(kTrustSettings), SQLITE_STATIC);
        sqlite3_bind_blob(st, 4, der.bytes, (int)der.length, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) fail([NSString stringWithFormat:@"couldn't add %@", root[@"name"]], db);
        sqlite3_finalize(st);
        [state addObject:hex];
        added++;
        printf("  + %s\n", [root[@"name"] UTF8String]);
    }

    // Roots an older version added that this version no longer ships.
    for (NSString *hex in [state copy]) {
        if ([wanted containsObject:hex]) continue;
        deleteRow(db, column, dataFromHex(hex));
        [state removeObject:hex];
        dropped++;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) fail(@"couldn't save changes", db);
    sqlite3_close(db);
    saveState(state);

    printf("Ben's Cert Fix: added %d root certificate%s", added, added == 1 ? "" : "s");
    if (already) printf(", %d were already trusted", already);
    if (dropped) printf(", removed %d old one%s", dropped, dropped == 1 ? "" : "s");
    printf(".\n");
    return 0;
}

static int removeAll(void) {
    NSMutableSet *state = loadState();
    if (state.count == 0) {
        printf("Ben's Cert Fix: nothing to remove.\n");
        return 0;
    }
    if (access(DB_PATH, F_OK) != 0) { saveState([NSSet set]); return 0; }
    sqlite3 *db = openStore();
    NSString *column = hashColumn(db);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) fail(@"store is busy", db);
    for (NSString *hex in state) deleteRow(db, column, dataFromHex(hex));
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) fail(@"couldn't save changes", db);
    sqlite3_close(db);
    printf("Ben's Cert Fix: removed %lu root certificate%s.\n", (unsigned long)state.count, state.count == 1 ? "" : "s");
    saveState([NSSet set]);
    return 0;
}

static int status(void) {
    NSArray *roots = loadRoots();
    if (access(DB_PATH, F_OK) != 0) {
        printf("No user trust store yet: none of the %lu roots are installed.\n", (unsigned long)roots.count);
        return 0;
    }
    sqlite3 *db = openStore();
    NSString *column = hashColumn(db);
    int present = 0;
    for (NSDictionary *root in roots) {
        BOOL ok = rowExists(db, column, root[column]);
        present += ok;
        printf("  [%s] %s\n", ok ? "x" : " ", [root[@"name"] UTF8String]);
    }
    sqlite3_close(db);
    printf("%d of %lu roots trusted.\n", present, (unsigned long)roots.count);
    return 0;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            fprintf(stderr, "usage: benscertfix install|remove|status\n");
            return 2;
        }
        if (geteuid() != 0 && strcmp(argv[1], "status") != 0) {
            fprintf(stderr, "benscertfix: must run as root\n");
            return 1;
        }
        if (strcmp(argv[1], "install") == 0) return install();
        if (strcmp(argv[1], "remove") == 0) return removeAll();
        if (strcmp(argv[1], "status") == 0) return status();
        fprintf(stderr, "usage: benscertfix install|remove|status\n");
        return 2;
    }
}
