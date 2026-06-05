#include <stdio.h>
#include "honeypot.h"

int main() {
    // 서버 시작 메시지
    printf("[*] Starting Web Honeypot Core Module...\n");
    
    // DB 초기화 --> attack_logs 테이블 초기화
    logger_init(DB_PATH);
    
    // 서버 시작, 포트 8080에서 소켓 열고 공격자 요청 대기
    server_start(PORT);
    
    return 0;
}
