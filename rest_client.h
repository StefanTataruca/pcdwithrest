#ifndef REST_CLIENT_H
#define REST_CLIENT_H

void make_rest_request(const char *url, char *response, const char *username, const char *password);
int rest_check_user(const char *username, const char *password);
void rest_add_user(const char *username, const char *password);
int rest_login(const char *username, const char *password);
int rest_register(const char *username, const char *password);

#endif // REST_CLIENT_H
