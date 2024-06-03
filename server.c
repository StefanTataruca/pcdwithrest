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
#include "db.h"

// Declare the rest_register function
int rest_register(const char *username, const char *password);

#define UNIX_SOCKET_PATH "/tmp/admin_socket"
#define INET_PORT 12345
#define REST_PORT 8888
#define BUFFER_SIZE 256
void handle_client(int client_fd);

void trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) {
        str++;
    }
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';
}
void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear buffer

    while (read(client_fd, buffer, BUFFER_SIZE) > 0) {
        printf("Debug: Received raw data: %s\n", buffer);
        char command[BUFFER_SIZE], username[BUFFER_SIZE], password[BUFFER_SIZE];
        sscanf(buffer, "%s %s %s", command, username, password);
        trim_whitespace(username);
        trim_whitespace(password);

        printf("Debug: Processed command: %s, username: %s, password: %s\n", command, username, password);

        if (strcmp(command, "LOGIN") == 0) {

            if (db_check_user(username, password)) {
                snprintf(buffer, sizeof(buffer), "Login successful");
            } else {
                snprintf(buffer, sizeof(buffer), "Login failed");
            }
            printf("Debug: Sending response: %s\n", buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
            memset(username, 0, BUFFER_SIZE);
            memset(password, 0, BUFFER_SIZE); // Clear buffers
            break;
        } else if (strcmp(command, "REGISTER") == 0) {
            if (!db_user_exists(username)) {
                db_add_user(username, password);
                snprintf(buffer, sizeof(buffer), "User registered successfully");
            } else {
                snprintf(buffer, sizeof(buffer), "Username already exists");
            }
            printf("Debug: Sending response: %s\n", buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
            memset(username, 0, BUFFER_SIZE);
            memset(password, 0, BUFFER_SIZE); // Clear buffers
            break;
        }
        memset(buffer, 0, BUFFER_SIZE);  // Clear buffer after processing
    }
    close(client_fd);
}



// Rest of your code...

struct ConnectionInfo {
    struct MHD_PostProcessor *pp;
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    };



static int send_cors_headers(struct MHD_Connection *connection, struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
    return MHD_YES;
}

static int check_user(void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method, const char *version,
                      const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    const char *username = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "username");
    const char *password = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "password");

    if (username == NULL || password == NULL) {
        const char *error = "Username or password not provided";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }

    trim_whitespace((char *)username);
    trim_whitespace((char *)password);

    if (db_check_user(username, password)) {
        const char *response_msg = "user exists";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    } else {
        const char *response_msg = "user does not exist";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
}

static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key, const char *filename,
                        const char *content_type, const char *transfer_encoding, const char *data, uint64_t off, size_t size) {
    struct ConnectionInfo *con_info = coninfo_cls;
    if (0 == strcmp(key, "username")) {
        if ((size > 0) && (size <= BUFFER_SIZE)) {
            strncpy(con_info->username, data, size);
            con_info->username[size] = '\0';
        } else {
            return MHD_NO;
        }
    } else if (0 == strcmp(key, "password")) {
        if ((size > 0) && (size <= BUFFER_SIZE)) {
            strncpy(con_info->password, data, size);
            con_info->password[size] = '\0';
        } else {
            return MHD_NO;
        }
    }
    return MHD_YES;
}

static int add_user(void *cls, struct MHD_Connection *connection,
                    const char *url, const char *method, const char *version,
                    const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    struct ConnectionInfo *con_info = *con_cls;
    if (NULL == con_info) {
        con_info = malloc(sizeof(struct ConnectionInfo));
        con_info->pp = MHD_create_post_processor(connection, BUFFER_SIZE, iterate_post, con_info);
        *con_cls = con_info;
        return MHD_YES;
    }

    MHD_post_process(con_info->pp, upload_data, *upload_data_size);
    if (*upload_data_size != 0) {
        return MHD_YES;
    }

    const char *username = con_info->username;
    const char *password = con_info->password;

    if (username == NULL || password == NULL) {
        const char *error = "Username or password not provided";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        return ret;
    }

    trim_whitespace((char *)username);
    trim_whitespace((char *)password);

    if (!db_user_exists(username)) {
        db_add_user(username, password);
        const char *response_msg = "user added successfully";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    } else {
        const char *response_msg = "username already exists";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_CONFLICT, response);
        MHD_destroy_response(response);
        return ret;
    }
}

static void request_completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
    if (NULL == *con_cls) return;
    struct ConnectionInfo *con_info = *con_cls;
    if (NULL != con_info->pp) {
        MHD_destroy_post_processor(con_info->pp);
    }
    free(con_info);
    *con_cls = NULL;
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

    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, REST_PORT, NULL, NULL, &check_user, NULL,
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
            handle_client(client_fd);
        }

        if (FD_ISSET(inet_socket_fd, &read_fds)) {
            if ((client_fd = accept(inet_socket_fd, NULL, NULL)) == -1) {
                perror("accept error");
                exit(-1);
            }
            handle_client(client_fd);
        }
    }

    MHD_stop_daemon(daemon);
    close(unix_socket_fd);
    close(inet_socket_fd);
    return 0;
}
