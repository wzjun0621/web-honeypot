#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <pthread.h>
#include "honeypot.h"

static sqlite3 *db;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

// 현재 시각을 ISO 8601 형식으로 포맷한다.
void get_current_timestamp(char *buf, int size) {
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", t);
}

void logger_init(const char *db_path) {
    // 멀티스레드 환경을 위 직렬화 모드 설정
    sqlite3_config(SQLITE_CONFIG_SERIALIZED);

    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "[-] Cannot open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    // WAL 모드 활성
    const char *sql_wal = "PRAGMA journal_mode=WAL;";
    sqlite3_exec(db, sql_wal, 0, 0, 0);

    // attack_logs 테이블이 없을 때만 생성
    const char *sql_create = 
        "CREATE TABLE IF NOT EXISTS attack_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, "
        "ip TEXT NOT NULL, "
        "method TEXT NOT NULL, "
        "path TEXT NOT NULL, "
        "user_agent TEXT, "
        "body TEXT, "
        "attack_type TEXT"
        ");";
    
    char *err_msg = 0;
    // 테이블 생성 실패 시 오류 출력 종료
    if (sqlite3_exec(db, sql_create, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "[-] SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        exit(1);
    }
    printf("[+] Database initialized successfully. (WAL mode)\n");
}

void log_request(const HttpRequest *req) {
    const char *sql = "INSERT INTO attack_logs (timestamp, ip, method, path, user_agent, body, attack_type) "
                      "VALUES (?, ?, ?, ?, ?, ?, NULL);";
    
    sqlite3_stmt *stmt;
    
    pthread_mutex_lock(&db_mutex);
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        // SQL 인젝션 방지
        sqlite3_bind_text(stmt, 1, req->timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, req->ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, req->method, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, req->path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, req->user_agent, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, req->body, -1, SQLITE_TRANSIENT);

        // INSERT 실행
        sqlite3_step(stmt);
        // 사용한 메모리 해제
        sqlite3_finalize(stmt);
    } else {
        // SQL문 준비 실패 시 오류 출력
        fprintf(stderr, "[-] Failed to prepare log statement.\n");
    }
    
    pthread_mutex_unlock(&db_mutex);
}
