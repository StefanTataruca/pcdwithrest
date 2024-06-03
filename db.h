#ifndef DB_H
#define DB_H

int db_user_exists(const char *username);
int db_check_user(const char *username, const char *password);
void db_add_user(const char *username, const char *password);
void db_init();

#endif