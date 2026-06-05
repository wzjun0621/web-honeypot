#include <stdio.h>
#include <string.h>
#include "honeypot.h"

void http_parse(const char *raw, HttpRequest *req) {
    // 각 요청된 값을 초기화한다. 이전의 데이터가 남아있을 수 있기 때문.
    memset(req->method, 0, sizeof(req->method));
    memset(req->path, 0, sizeof(req->path));
    memset(req->user_agent, 0, sizeof(req->user_agent));
    memset(req->body, 0, sizeof(req->body));

    // 메서드와 경로를 추출한다. 버퍼 오버플로우 방지를 위해 15글자, 1023글자까지만 입력받는다.
    sscanf(raw, "%15s %1023s", req->method, req->path);

    // 전체 요청 문자열에서 "User-Agent: " 문자열 위치를 찾고 뒤의 문자열을 가져온다.
    // 결과적으로 공격자의 OS, 브라우저 등을 알 수 있다.
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

    // Body 추출 (SQL 인젝션 방지)
    char *body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(req->body, body_start, sizeof(req->body) - 1);
    }
}
