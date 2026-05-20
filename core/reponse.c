#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "honeypot.h"

// HTTP 응답 템플릿
const char *HTTP_200_LOGIN = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n\r\n"
    "<html><body><h1>Admin Login</h1><form method='POST'><input name='username'/><input type='password' name='password'/><input type='submit'/></form></body></html>";

const char *HTTP_200_ENV = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n\r\n"
    "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=supersecret_honeypot\n";

const char *HTTP_404 = 
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n\r\n"
    "<html><body><h1>404 Not Found</h1></body></html>";

void send_fake_response(int fd, const char *path) {
    if (strstr(path, "admin") || strstr(path, "login") || strstr(path, "signin") || strstr(path, "wp-login")) {
        write(fd, HTTP_200_LOGIN, strlen(HTTP_200_LOGIN));
    } else if (strcmp(path, "/.env") == 0) {
        write(fd, HTTP_200_ENV, strlen(HTTP_200_ENV));
    } else {
        write(fd, HTTP_404, strlen(HTTP_404));
    }
}