#ifndef DB_H
#define DB_H

int db_user_exists(const char *username);
int db_check_user(const char *username, const char *password, int *role);
void db_add_user(const char *username, const char *password);
void db_init();
int db_is_user_blocked(const char *username);
int db_block_user(const char *username);
int db_unblock_user(const char *username);

#endif