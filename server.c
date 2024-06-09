#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <microhttpd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include "db.h"
#include "rest_handlers.h"

#define MAX_USERS 100
#define UNIX_SOCKET_PATH "/tmp/admin_socket"
#define INET_PORT 12345
#define REST_PORT 8888
#define BUFFER_SIZE 256
#define UPLOAD_BUFFER_SIZE 1024

void *handle_client(void *arg);
void cleanup_resources();
void handle_signal(int signal);

typedef struct {
    char username[BUFFER_SIZE];
    int socket_fd;
    int is_blocked; // Adaugă acest câmp
} User;

User connected_users[MAX_USERS];
int num_connected_users = 0;

pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

static int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url,
                                const char *method, const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    if (0 == strcmp(url, "/upload_xml"))
        return upload_xml_rest(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/download_json"))
        return download_json_rest(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/check_user"))
        return check_user_rest(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/add_user"))
        return add_user_rest(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    return MHD_NO;
}


void add_user(const char *username, int socket_fd) {
    pthread_mutex_lock(&users_mutex);
    if (num_connected_users < MAX_USERS) {
        strcpy(connected_users[num_connected_users].username, username);
        connected_users[num_connected_users].socket_fd = socket_fd;
        num_connected_users++;
    }
    pthread_mutex_unlock(&users_mutex);
}

void remove_user(int socket_fd) {
    pthread_mutex_lock(&users_mutex);
    for (int i = 0; i < num_connected_users; i++) {
        if (connected_users[i].socket_fd == socket_fd) {
            connected_users[i] = connected_users[num_connected_users - 1];
            num_connected_users--;
            break;
        }
    }
    pthread_mutex_unlock(&users_mutex);
}

void view_connected_users(char *buffer) {
    pthread_mutex_lock(&users_mutex);
    snprintf(buffer, BUFFER_SIZE, "Connected users:\n");
    for (int i = 0; i < num_connected_users; i++) {
        strncat(buffer, connected_users[i].username, BUFFER_SIZE - strlen(buffer) - 1);
        strncat(buffer, "\n", BUFFER_SIZE - strlen(buffer) - 1);
    }
    pthread_mutex_unlock(&users_mutex);
}

void view_logs(char *buffer) {
    FILE *log_file = fopen("server.log", "r");
    if (log_file) {
        size_t len = fread(buffer, 1, BUFFER_SIZE - 1, log_file);
        buffer[len] = '\0';
        fclose(log_file);
    } else {
        snprintf(buffer, BUFFER_SIZE, "Failed to read logs");
    }
}

int delete_file(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (dot && (strcmp(dot, ".json") == 0 || strcmp(dot, ".xml") == 0)) {
        return remove(filename) == 0;
    }
    return 0;
}

void disconnect_user(const char *username) {
    pthread_mutex_lock(&users_mutex);
    for (int i = 0; i < num_connected_users; i++) {
        if (strcmp(connected_users[i].username, username) == 0) {
            close(connected_users[i].socket_fd);
            connected_users[i] = connected_users[num_connected_users - 1];
            num_connected_users--;
            break;
        }
    }
    pthread_mutex_unlock(&users_mutex);
}

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    int is_unix_socket = *((int *)(arg + sizeof(int)));
    free(arg);

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    while (1) {
        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            break;
        }
        buffer[bytes_read] = '\0';

        printf("Debug: Received raw data: %s\n", buffer);
        char command[BUFFER_SIZE], username[BUFFER_SIZE], password[BUFFER_SIZE];
        int role;
        sscanf(buffer, "%s %s %s", command, username, password);
        trim_whitespace(username);
        trim_whitespace(password);

        if (strcmp(command, "LOGIN") == 0) {
            if (db_check_user(username, password, &role)) {
                if ((is_unix_socket && role == 1) || (!is_unix_socket && role == 0)) {
                    snprintf(buffer, sizeof(buffer), "Login successful");
                    add_user(username, client_fd);
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, sizeof(log_msg), "User %.100s logged in as %s", username, is_unix_socket ? "admin" : "simple");
                    log_message(log_msg);
                } else {
                    snprintf(buffer, sizeof(buffer), "Access denied");
                }
            } else {
                snprintf(buffer, sizeof(buffer), "Login failed");
            }
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "REGISTER") == 0) {
            if (!db_user_exists(username)) {
                db_add_user(username, password);
                snprintf(buffer, sizeof(buffer), "User registered successfully");
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, sizeof(log_msg), "User %.100s registered as simple", username);
                log_message(log_msg);
            } else {
                snprintf(buffer, sizeof(buffer), "Username already exists");
            }
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "VIEW_USERS") == 0) {
            view_connected_users(buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "VIEW_LOGS") == 0) {
            view_logs(buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "BLOCK_USER") == 0) {
            char target_username[BUFFER_SIZE];
            sscanf(buffer + strlen("BLOCK_USER "), "%s", target_username);
            int result = db_block_user(target_username);
            if (result == 1) {
                snprintf(buffer, sizeof(buffer), "User %.100s blocked successfully", target_username);
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, sizeof(log_msg), "User %.100s blocked", target_username);
                log_message(log_msg);
                disconnect_user(target_username);
            } else if (result == -1) {
                snprintf(buffer, sizeof(buffer), "User %.100s is already blocked", target_username);
            } else {
                snprintf(buffer, sizeof(buffer), "Failed to block user %.100s", target_username);
            }
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "UNBLOCK_USER") == 0) {
            char target_username[BUFFER_SIZE];
            sscanf(buffer + strlen("UNBLOCK_USER "), "%s", target_username);
            int result = db_unblock_user(target_username);
            if (result == 1) {
                snprintf(buffer, sizeof(buffer), "User %.100s unblocked successfully", target_username);
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, sizeof(log_msg), "User %.100s unblocked", target_username);
                log_message(log_msg);
            } else if (result == -1) {
                snprintf(buffer, sizeof(buffer), "User %.100s is already unblocked", target_username);
            } else {
                snprintf(buffer, sizeof(buffer), "Failed to unblock user %.100s", target_username);
            }
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "DELETE_FILE") == 0) {
            char filename[BUFFER_SIZE];
            sscanf(buffer + strlen("DELETE_FILE "), "%s", filename);
            if (delete_file(filename)) {
                snprintf(buffer, sizeof(buffer), "File %.100s deleted successfully", filename);
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, sizeof(log_msg), "File %.100s deleted", filename);
                log_message(log_msg);
            } else {
                snprintf(buffer, sizeof(buffer), "Failed to delete file %.100s", filename);
            }
            write(client_fd, buffer, strlen(buffer) + 1);
        } else if (strcmp(command, "LOGOUT") == 0) {
            snprintf(buffer, sizeof(buffer), "Logged out successfully");
            write(client_fd, buffer, strlen(buffer) + 1);
            remove_user(client_fd);
            break;
        }
        memset(buffer, 0, BUFFER_SIZE);
    }
    close(client_fd);
    return NULL;
}
void cleanup_resources() {
    if (unlink(UNIX_SOCKET_PATH) == -1 && errno != ENOENT) {
        perror("Failed to unlink UNIX socket");
    }

    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command), "fuser -k %d/tcp", INET_PORT);
    system(command);

    snprintf(command, sizeof(command), "fuser -k %d/tcp", REST_PORT);
    system(command);
}

void handle_signal(int signal) {
    cleanup_resources();
    exit(0);
}

int main() {
    int unix_socket_fd, inet_socket_fd, client_fd;
    struct sockaddr_un unix_server_addr;
    struct sockaddr_in inet_server_addr;
    fd_set read_fds;
    struct MHD_Daemon *daemon;

    cleanup_resources();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    db_init();

    if ((unix_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    if ((inet_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&unix_server_addr, 0, sizeof(struct sockaddr_un));
    unix_server_addr.sun_family = AF_UNIX;
    strncpy(unix_server_addr.sun_path, UNIX_SOCKET_PATH, sizeof(unix_server_addr.sun_path) - 1);

    memset(&inet_server_addr, 0, sizeof(struct sockaddr_in));
    inet_server_addr.sin_family = AF_INET;
    inet_server_addr.sin_port = htons(INET_PORT);
    inet_server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(unix_socket_fd, (struct sockaddr *)&unix_server_addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (bind(inet_socket_fd, (struct sockaddr *)&inet_server_addr, sizeof(struct sockaddr_in)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (listen(unix_socket_fd, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    if (listen(inet_socket_fd, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, REST_PORT, NULL, NULL, &answer_to_connection, NULL,
                              MHD_OPTION_NOTIFY_COMPLETED, request_completed_callback, NULL,
                              MHD_OPTION_END);
    if (NULL == daemon) return 1;

    printf("Server is running...\n");

    sleep(1);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(unix_socket_fd, &read_fds);
        FD_SET(inet_socket_fd, &read_fds);
        int max_fd = (unix_socket_fd > inet_socket_fd) ? unix_socket_fd : inet_socket_fd;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select error");
            exit(-1);
        }

        if (FD_ISSET(unix_socket_fd, &read_fds)) {
            if ((client_fd = accept(unix_socket_fd, NULL, NULL)) == -1) {
                perror("accept error");
                exit(-1);
            }

            int *arg = malloc(2 * sizeof(int));
            arg[0] = client_fd;
            arg[1] = 1;
            pthread_t thread;
            if (pthread_create(&thread, NULL, handle_client, arg) != 0) {
                perror("Failed to create thread");
                close(client_fd);
                free(arg);
            } else {
                pthread_detach(thread);
            }
        }

        if (FD_ISSET(inet_socket_fd, &read_fds)) {
            if ((client_fd = accept(inet_socket_fd, NULL, NULL)) == -1) {
                perror("accept error");
                exit(-1);
            }

            int *arg = malloc(2 * sizeof(int));
            arg[0] = client_fd;
            arg[1] = 0;
            pthread_t thread;
            if (pthread_create(&thread, NULL, handle_client, arg) != 0) {
                perror("Failed to create thread");
                close(client_fd);
                free(arg);
            } else {
                pthread_detach(thread);
            }
        }
    }

    MHD_stop_daemon(daemon);
    close(unix_socket_fd);
    close(inet_socket_fd);
    return 0;
}
