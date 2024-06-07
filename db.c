#include "db.h"
#include <stdio.h>
#include <sqlite3.h>
#include <string.h>

sqlite3 *db;
char *err_msg = 0;

void db_init() {
    int rc = sqlite3_open("users.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    const char *sql = "CREATE TABLE IF NOT EXISTS Users("
                      "username TEXT PRIMARY KEY, "
                      "password TEXT, "
                      "role INTEGER DEFAULT 0);";

    printf("Initializing database\n");
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("Database initialized successfully.\n");
    }
}

void db_add_user(const char *username, const char *password) {
    char *sql = sqlite3_mprintf("INSERT INTO Users (username, password, role) VALUES (%Q, %Q, %d)", username, password, 0);

    printf("Executing statement for db_add_user\n");
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("User %s added successfully.\n", username);
    }

    sqlite3_free(sql);
}

int db_check_user(const char *username, const char *password, int *role) {
    sqlite3_stmt *res;
    int rc;
    const char *sql = "SELECT role FROM Users WHERE username = ? AND password = ?";

    printf("Preparing statement for db_check_user\n");
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(res, 2, password, -1, SQLITE_STATIC);

    printf("Executing statement for db_check_user\n");
    rc = sqlite3_step(res);

    if (rc == SQLITE_ROW) {
        *role = sqlite3_column_int(res, 0);
    } else {
        fprintf(stderr, "Failed to step statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(res);
        return 0;
    }

    sqlite3_finalize(res);
    printf("db_check_user: username=%s, password=%s, role=%d\n", username, password, *role);
    return 1;
}

int db_user_exists(const char *username) {
    sqlite3_stmt *res;
    int rc;
    const char *sql = "SELECT COUNT(*) FROM Users WHERE username = ?";

    printf("Preparing statement for db_user_exists\n");
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(res, 1, username, -1, SQLITE_STATIC);

    printf("Executing statement for db_user_exists\n");
    rc = sqlite3_step(res);
    int count = 0;
    if (rc == SQLITE_ROW) {
        count = sqlite3_column_int(res, 0);
    } else {
        fprintf(stderr, "Failed to step statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(res);
    printf("db_user_exists: username=%s, count=%d\n", username, count);
    return count > 0;
}
