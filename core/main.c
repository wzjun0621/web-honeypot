#include <stdio.h>
#include "honeypot.h"

int main() {
    printf("[*] Starting Web Honeypot Core Module...\n");
    
    // DB 초기화
    logger_init(DB_PATH);
    
    // 서버 시작 (블로킹)
    server_start(PORT);
    
    return 0;
}