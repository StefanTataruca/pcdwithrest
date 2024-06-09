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
#include "lxml.h"
#include "json.h"

// Declare the functions before using them
static int check_user(void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method, const char *version,
                      const char *upload_data, size_t *upload_data_size, void **con_cls);
static int add_user(void *cls, struct MHD_Connection *connection,
                    const char *url, const char *method, const char *version,
                    const char *upload_data, size_t *upload_data_size, void **con_cls);

#define UNIX_SOCKET_PATH "/tmp/admin_socket"
#define INET_PORT 12345
#define REST_PORT 8888
#define BUFFER_SIZE 256
#define UPLOAD_BUFFER_SIZE 1024

void *handle_client(void *arg);
void cleanup_resources();
void handle_signal(int signal);

struct UploadInfo {
    char buffer[UPLOAD_BUFFER_SIZE];
    size_t buffer_size;
    FILE *fp;
};
static void log_message(const char *message) {
    FILE *log_file = fopen("server.log", "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(log_file, "%04d-%02d-%02d %02d:%02d:%02d: %s\n", 
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, 
            t->tm_hour, t->tm_min, t->tm_sec, message);
    fclose(log_file);
}
static void add_cors_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
}

static int upload_xml(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                      const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    struct UploadInfo *upload_info = *con_cls;
    if (NULL == upload_info) {
        upload_info = malloc(sizeof(struct UploadInfo));
        if (NULL == upload_info)
            return MHD_NO;
        upload_info->buffer_size = 0;
        upload_info->fp = fopen("uploaded.xml", "wb");
        if (NULL == upload_info->fp) {
            free(upload_info);
            return MHD_NO;
        }
        *con_cls = upload_info;
        return MHD_YES;
    }

    if (0 != *upload_data_size) {
        fwrite(upload_data, 1, *upload_data_size, upload_info->fp);
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        fclose(upload_info->fp);

        // Conversia XML la JSON
        XMLDocument doc;
        if (XMLDocument_load(&doc, "uploaded.xml")) {
            cJSON *json = XMLDocumentToJSON(&doc);
            SaveJSONToFile("converted.json", json);
            cJSON_Delete(json);
            XMLDocument_free(&doc);
        }

        const char *page = "<html><body>File uploaded and converted successfully.</body></html>";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        free(upload_info);
        *con_cls = NULL;
        return ret;
    }
}

static int download_json(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                         const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    FILE *fp = fopen("converted.json", "rb");
    if (!fp) {
        return MHD_NO;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    struct MHD_Response *response = MHD_create_response_from_buffer(file_size, file_data, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Disposition", "attachment; filename=\"converted.json\"");
    add_cors_headers(response);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}



static int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url,
                                const char *method, const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    if (0 == strcmp(url, "/upload_xml"))
        return upload_xml(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/download_json"))
        return download_json(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/check_user"))
        return check_user(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    if (0 == strcmp(url, "/add_user"))
        return add_user(cls, connection, url, method, version, upload_data, upload_data_size, con_cls);

    return MHD_NO;
}


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

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    int is_unix_socket = *((int *)(arg + sizeof(int)));
    free(arg);

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE); 

    while (read(client_fd, buffer, BUFFER_SIZE) > 0) {
        printf("Debug: Received raw data: %s\n", buffer);
        char command[BUFFER_SIZE], username[BUFFER_SIZE], password[BUFFER_SIZE];
        int role;
        sscanf(buffer, "%s %s %s", command, username, password);
        trim_whitespace(username);
        trim_whitespace(password);

        printf("Debug: Processed command: %s, username: %s, password: %s\n", command, username, password);

        if (strcmp(command, "LOGIN") == 0) {
            if (db_check_user(username, password, &role)) {
                if ((is_unix_socket && role == 1) || (!is_unix_socket && role == 0)) {
                    snprintf(buffer, sizeof(buffer), "Login successful");
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, sizeof(log_msg), "User %.100s logged in as %s", username, is_unix_socket ? "admin" : "simple");
                    log_message(log_msg);
                } else {
                    snprintf(buffer, sizeof(buffer), "Access denied");
                }
            } else {
                snprintf(buffer, sizeof(buffer), "Login failed");
            }
            printf("Debug: Sending response: %s\n", buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
            memset(username, 0, BUFFER_SIZE);
            memset(password, 0, BUFFER_SIZE);
            memset(buffer, 0, BUFFER_SIZE); 
            break;
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
            printf("Debug: Sending response: %s\n", buffer);
            write(client_fd, buffer, strlen(buffer) + 1);
            memset(username, 0, BUFFER_SIZE);
            memset(password, 0, BUFFER_SIZE);
            memset(buffer, 0, BUFFER_SIZE);  
            break;
        }
        memset(buffer, 0, BUFFER_SIZE);  
    }
    close(client_fd);
    return NULL;
}

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

    int role;
    if (db_check_user(username, password, &role)) {
        if (role == 1) {  // Admin role
            const char *response_msg = "Access denied";
            struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
            send_cors_headers(connection, response);
            int ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
            MHD_destroy_response(response);
            return ret;
        } else {
            const char *response_msg = "user exists";
            struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
            send_cors_headers(connection, response);
            int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, sizeof(log_msg), "User %s logged in as rest", username);
            log_message(log_msg);
            return ret;
        }
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
        if ((size > 0) && (size < BUFFER_SIZE)) {
            strncpy(con_info->username, data, size);
            con_info->username[size] = '\0';
            printf("Debug: Username received: %s\n", con_info->username);
        } else {
            return MHD_NO;
        }
    } else if (0 == strcmp(key, "password")) {
        if ((size > 0) && (size < BUFFER_SIZE)) {
            strncpy(con_info->password, data, size);
            con_info->password[size] = '\0';
            printf("Debug: Password received: %s\n", con_info->password);
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

    if (*upload_data_size != 0) {
        MHD_post_process(con_info->pp, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    const char *username = con_info->username;
    const char *password = con_info->password;

    printf("Debug: Received POST data - Username: %s, Password: %s\n", username, password);

    if (username == NULL || password == NULL || strlen(username) == 0 || strlen(password) == 0) {
        const char *error = "Username or password not provided";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
        MHD_destroy_response(response);
        printf("Debug: Missing username or password\n");
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
        printf("Debug: User added successfully\n");
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, sizeof(log_msg), "User %.100s registered as rest", username);
        log_message(log_msg);
        return ret;
    } else {
        const char *response_msg = "username already exists";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
        send_cors_headers(connection, response);
        int ret = MHD_queue_response(connection, MHD_HTTP_CONFLICT, response);
        MHD_destroy_response(response);
        printf("Debug: Username already exists\n");
        return ret;
    }
}


static void request_completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
    if (NULL == *con_cls) return;
    struct ConnectionInfo *con_info = *con_cls;
    if (NULL != con_info->pp) {
        MHD_destroy_post_processor(con_info->pp);
    }

    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "User %.100s disconnected", con_info->username);
    log_message(log_msg);

    free(con_info);
    *con_cls = NULL;
    printf("Debug: Request completed and resources freed\n");
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
