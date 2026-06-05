/* honeypot.h - 팀원 담당 */
#ifndef HONEYPOT_H
#define HONEYPOT_H

void server_start(int port); // server.c에 구현된 함수 선언
void http_parse(const char *raw, char *method, char *path, char *user_agent, char *body); // http_parser.c에 구현된 함수 선언
// logger.c에 구현된 함수 선언
void log_request(const HttpRequest *req);
// reponse.c에 구현된 함수 선언
void send_fake_response(int client_fd, const char *path);

#endif
