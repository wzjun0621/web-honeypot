#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "honeypot.h"

// 스레드에 넘겨줄 클라이언트 정보 구조체
typedef struct {
    int client_fd;
    char ip[46];
} ClientInfo;

void *client_handler(void *arg) {
    ClientInfo *info = (ClientInfo *)arg;
    int fd = info->client_fd;
    
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    
    // 타임아웃 방지 및 빠른 처리를 위해 한번만 읽음
    ssize_t bytes_read = read(fd, buffer, BUF_SIZE - 1);
    
    if (bytes_read > 0) {
        HttpRequest req;
        memset(&req, 0, sizeof(HttpRequest));
        
        strncpy(req.ip, info->ip, sizeof(req.ip) - 1);
        get_current_timestamp(req.timestamp, sizeof(req.timestamp));
        
        // HTTP 파싱 및 로그 기록
        http_parse(buffer, &req);
        
        // 빈 요청이 아니면 기록
        if (strlen(req.method) > 0) {
            log_request(&req);
            printf("[+] Logged request from %s: %s %s\n", req.ip, req.method, req.path);
        }
        
        // 가짜 응답 전송
        send_fake_response(fd, req.path);
    }
    
    close(fd);
    free(info);
    pthread_exit(NULL);
}

void server_start(int port) {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[-] Socket creation failed");
        exit(1);
    }
    
    // SO_REUSEADDR 설정 (포트 바인딩 에러 방지)
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Bind failed");
        exit(1);
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("[-] Listen failed");
        exit(1);
    }
    
    printf("[*] Honeypot Core listening on port %d...\n", port);
    
    while (1) {
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("[-] Accept failed");
            continue;
        }
        
        // 클라이언트 정보 할당 (스레드에서 해제)
        ClientInfo *info = malloc(sizeof(ClientInfo));
        info->client_fd = client_fd;
        inet_ntop(AF_INET, &client_addr.sin_addr, info->ip, sizeof(info->ip));
        
        // 새 스레드 생성 (스캐너의 동시 접속 대응)
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, (void *)info) != 0) {
            perror("[-] Thread creation failed");
            close(client_fd);
            free(info);
        } else {
            // 스레드 자원 자동 반환 (join 불필요)
            pthread_detach(tid);
        }
    }
    
    close(server_fd);
}