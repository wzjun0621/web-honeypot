#include <stdio.h>
#include <string.h>
#include "honeypot.h"

void http_parse(const char *raw, HttpRequest *req) {
    // 초기화
    memset(req->method, 0, sizeof(req->method));
    memset(req->path, 0, sizeof(req->path));
    memset(req->user_agent, 0, sizeof(req->user_agent));
    memset(req->body, 0, sizeof(req->body));

    // 첫 줄 파싱 (Method Path HTTP/1.x)
    sscanf(raw, "%15s %1023s", req->method, req->path);

    // User-Agent 추출
    const char *ua_header = "User-Agent: ";
    char *ua_start = strstr(raw, ua_header);
    if (ua_start) {
        ua_start += strlen(ua_header);
        char *ua_end = strstr(ua_start, "\r\n");
        if (ua_end) {
            size_t len = ua_end - ua_start;
            if (len >= sizeof(req->user_agent)) len = sizeof(req->user_agent) - 1;
            strncpy(req->user_agent, ua_start, len);
        }
    }

    // Body 추출 (\r\n\r\n 이후)
    char *body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req->body, body_start, sizeof(req->body) - 1);
    }
}