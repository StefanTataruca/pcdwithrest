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
#include "conversion.h"
#include "rest_handlers.h"
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_USERS 100
#define UNIX_SOCKET_PATH "/tmp/admin_socket"
#define INET_PORT 12345
#define REST_PORT 8888
#define MAX_BUFFER 1024
#define MAX_FILE_PATH 512
#define MAX_PATH 1024
#define LARGE_BUFFER_SIZE 8192
#define MAX_ADMIN_THREADS 5
#define MAX_USER_THREADS 10
char converted_json_filename[MAX_FILE_PATH];
void *handle_client(void *arg);
void trim_trailing_slash(char *str);
void cleanup_resources();
void handle_upload(int client_fd, const char *username, const char *client_file_path);
void handle_download(int client_fd, const char *username, const char *download_dir);

void handle_signal(int signal);
typedef struct {
    char username[BUFFER_SIZE];
    int socket_fd;
} User;

User connected_users[MAX_USERS];
int num_connected_users = 0;
int admin_connected = 0;
pthread_mutex_t admin_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

void trim_trailing_slash(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '/') {
        str[len - 1] = '\0';
    }
}

int copy_file(const char *src, const char *dst) {
    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0) {
        perror("Failed to open source file");
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644); // Using 0644 to be less permissive
    if (out_fd < 0) {
        perror("Failed to open destination file");
        close(in_fd);
        return -1;
    }

    char buffer[1024];
    ssize_t bytes_read, bytes_written;

    while ((bytes_read = read(in_fd, buffer, sizeof(buffer))) > 0) {
        char *ptr = buffer;
        while (bytes_read > 0) {
            bytes_written = write(out_fd, ptr, bytes_read);
            if (bytes_written <= 0) {
                perror("Failed to write to destination file");
                close(in_fd);
                close(out_fd);
                return -1;
            }
            bytes_read -= bytes_written;
            ptr += bytes_written;
        }
    }

    if (bytes_read < 0) {
        perror("Failed to read from source file");
        close(in_fd);
        close(out_fd);
        return -1;
    }

    close(in_fd);
    close(out_fd);
    return 0;
}

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

char *load_file_content(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    // Seek to the end 
    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the file content
    char *buffer = malloc(size + 1); // +1 for the null terminator
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    // Read the file content into the buffer
    size_t read_size = fread(buffer, 1, size, file);
    if (read_size != size) {
        perror("Failed to read file content");
        free(buffer);
        fclose(file);
        return NULL;
    }

    // Null-terminate the buffer
    buffer[size] = '\0';

    // Close the file
    fclose(file);

    return buffer;
}


void handle_upload(int client_fd,const char *authenticated_username, const char *client_file_path) {
    char buffer[BUFFER_SIZE];
    FILE *file;
    ssize_t bytes_read;
    char file_name[BUFFER_SIZE];
    char *client_file_path_copy = strdup(client_file_path);  // Create a mutable copy of client_file_path

    if (client_file_path_copy == NULL) {
        perror("Failed to allocate memory");
        snprintf(buffer, sizeof(buffer), "Error: Server memory allocation failed.\n");
        write(client_fd, buffer, strlen(buffer));
        return;
    }

    // Extract the basename from the client's file path to prevent directory traversal attacks
    snprintf(file_name, sizeof(file_name), "%s", basename(client_file_path_copy));

    // Open the file for writing in the current directory
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "./%s", file_name);

    printf("Debug: Starting file upload: %s\n", full_path);

    file = fopen(full_path, "wb");
    if (!file) {
        perror("Failed to open file");
        snprintf(buffer, sizeof(buffer), "Error: Failed to open file on server.\n");
        write(client_fd, buffer, strlen(buffer));
        free(client_file_path_copy);  // Free the allocated memory
        return;
    }

    // Send acknowledgment to the client
    snprintf(buffer, sizeof(buffer), "ACK");
    write(client_fd, buffer, strlen(buffer));

    while ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate to safely use strstr

        // Check if the buffer contains the end-of-file marker
        char *eof_pos = strstr(buffer, "END_OF_FILE");
        if (eof_pos != NULL) {
            // Ensure that no data beyond "END_OF_FILE" is written to the file
            size_t eof_index = eof_pos - buffer;
            if (eof_index > 0) {
                fwrite(buffer, 1, eof_index, file); // Write data before "END_OF_FILE"
            }
            break;
        } else {
            fwrite(buffer, 1, bytes_read, file); // Write full buffer
        }
    }

    if (bytes_read < 0) {
        perror("Failed to read from socket");
        snprintf(buffer, sizeof(buffer), "Error: Failed to read from socket.\n");
        write(client_fd, buffer, strlen(buffer));
        fclose(file);
        free(client_file_path_copy);  // Free the allocated memory
        return;
    }

    fclose(file);
    free(client_file_path_copy);  // Free the allocated memory
    printf("Debug: Finished receiving file. Converting...\n");

    char json_file_path[MAX_FILE_PATH];
    char *file_name_without_ext = strtok(file_name, "."); // Remove the extension
    snprintf(json_file_path, sizeof(json_file_path), "./converted_%s_%s.json", authenticated_username, file_name);

    // Assume convert_xml_to_json is a function defined elsewhere
    if (convert_xml_to_json(full_path, json_file_path) != 0) {
        snprintf(buffer, sizeof(buffer), "Error: Failed to convert XML to JSON.\n");
        write(client_fd, buffer, strlen(buffer));
        return;
    }
    // Add log message for conversion
    char log_msg[2048]; // Increased buffer size
    snprintf(log_msg, sizeof(log_msg), "User %s converted file %s to %s", authenticated_username, full_path, json_file_path);
    log_message(log_msg);

    // Store the converted JSON filename in the global variable
    snprintf(converted_json_filename, sizeof(converted_json_filename), "converted_%s_%s.json", authenticated_username, file_name);

    snprintf(buffer, sizeof(buffer), "Success: File uploaded and converted successfully.\n");
    write(client_fd, buffer, strlen(buffer));
    fsync(client_fd);
    printf("Debug: File uploaded and converted successfully.\n");
    // Add log message for upload
    snprintf(log_msg, sizeof(log_msg), "User %s uploaded file %s", authenticated_username, client_file_path);
    log_message(log_msg);
}
void handle_download(int client_fd, const char *username, const char *download_dir) {
    char buffer[MAX_PATH];
    FILE *file;
    ssize_t bytes_read;

    // Ensure the buffer size is ample to avoid truncation
    char temp_download_path[MAX_PATH];
    char final_download_path[MAX_PATH];

    // Using snprintf safely by respecting buffer limits
    snprintf(temp_download_path, sizeof(temp_download_path), "./%s", converted_json_filename);
    snprintf(final_download_path, sizeof(final_download_path), "%s/%s", download_dir, converted_json_filename);

    file = fopen(temp_download_path, "rb");
    if (!file) {
        perror("Failed to open source file for reading");
        return;
    }

    write(client_fd, converted_json_filename, strlen(converted_json_filename) + 1);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (write(client_fd, buffer, bytes_read) != bytes_read) {
            perror("Failed to send file content to client");
            fclose(file);
            return;
        }
    }

    if (bytes_read < 0) {
        perror("Failed to read file for sending");
    }

    fclose(file);
    printf("Debug: Entire file sent to client.\n");

    // Add log message for download
    char log_msg[2048]; // Increased buffer size
    snprintf(log_msg, sizeof(log_msg), "User %s downloaded file %s", username, converted_json_filename);
    log_message(log_msg);

    // Send EOF marker
    snprintf(buffer, sizeof(buffer), "END_OF_FILE");
    write(client_fd, buffer, strlen(buffer) + 1);
    printf("Debug: Sent EOF marker to client.\n");
}



void disconnect_user(const char *username) {
    pthread_mutex_lock(&users_mutex);
    for (int i = 0; i < num_connected_users; i++) {
        if (strcmp(connected_users[i].username, username) == 0) {
            close(connected_users[i].socket_fd);
            connected_users[i] = connected_users[num_connected_users - 1];
            num_connected_users--;
            if (strcmp(username, "admin") == 0) {
                admin_connected = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&users_mutex);
}

void notify_and_disconnect_user(const char *username) {
    pthread_mutex_lock(&users_mutex);
    for (int i = 0; i < num_connected_users; i++) {
        if (strcmp(connected_users[i].username, username) == 0) {
            const char *message = "DISCONNECT";
            write(connected_users[i].socket_fd, message, strlen(message) + 1);
            close(connected_users[i].socket_fd);
            connected_users[i] = connected_users[num_connected_users - 1];
            num_connected_users--;
            if (strcmp(username, "admin") == 0) {
                admin_connected = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&users_mutex);
}


void handle_block_user(int client_fd, const char *username) {
    char buffer[BUFFER_SIZE];

    if (db_is_user_blocked(username)) {
        snprintf(buffer, sizeof(buffer), "User %s is already blocked.", username);
    } else if (db_block_user(username)) {
        snprintf(buffer, sizeof(buffer), "User %s blocked successfully.", username);
        notify_and_disconnect_user(username);  // Deconectează utilizatorul dacă este conectat
    } else {
        snprintf(buffer, sizeof(buffer), "Failed to block user %s.", username);
    }
    write(client_fd, buffer, strlen(buffer) + 1);  // Asigură-te că trimiți terminatorul null
}

void handle_unblock_user(int client_fd, const char *username) {
    char buffer[BUFFER_SIZE];

    if (!db_is_user_blocked(username)) {
        snprintf(buffer, sizeof(buffer), "User %s is not blocked.", username);
    } else if (db_unblock_user(username)) {
        snprintf(buffer, sizeof(buffer), "User %s unblocked successfully.", username);
    } else {
        snprintf(buffer, sizeof(buffer), "Failed to unblock user %s.", username);
    }
    write(client_fd, buffer, strlen(buffer) + 1);  // Asigură-te că trimiți terminatorul null
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
            if (strcmp(connected_users[i].username, "admin") == 0) {
                admin_connected = 0;
            }
            for (int j = i; j < num_connected_users - 1; j++) {
                connected_users[j] = connected_users[j + 1];
            }
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
void view_all_users(int client_fd) {
    char buffer[BUFFER_SIZE];
    char *user_list = malloc(LARGE_BUFFER_SIZE); // Dynamically allocate a larger buffer
    if (user_list == NULL) {
        snprintf(buffer, sizeof(buffer), "Error: Server memory allocation failed.");
        write(client_fd, buffer, strlen(buffer));
        return;
    }

    if (db_fetch_all_users(user_list, LARGE_BUFFER_SIZE) == 0) {
        snprintf(buffer, sizeof(buffer), "All users:\n%s", user_list);
        write(client_fd, buffer, strlen(buffer));
    } else {
        snprintf(buffer, sizeof(buffer), "Error fetching user list.");
        write(client_fd, buffer, strlen(buffer));
    }
    free(user_list);
}
void view_logs(int client_fd, const char *dir_path) {
    char log_file_path[] = "server.log"; // Path to the log file on the server
    char dest_path[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];   
    snprintf(dest_path, sizeof(dest_path), "%s/server.log", dir_path); // Create destination path

    // Copy log file to the specified directory
    if (copy_file(log_file_path, dest_path) == 0) {
        snprintf(buffer, BUFFER_SIZE, "Logs successfully saved to %s.", dir_path);
    } else {
        snprintf(buffer, BUFFER_SIZE, "Failed to save logs to %s.", dir_path);
    }
    write(client_fd, buffer, strlen(buffer) + 1);
}

int delete_file(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (dot && (strcmp(dot, ".json") == 0 || strcmp(dot, ".xml") == 0)) {
        return remove(filename) == 0;
    }
    return 0;
}

char *read_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Could not open file: %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *content = (char *)malloc(length + 1);
    if (!content) {
        fclose(file);
        printf("Memory allocation failed\n");
        return NULL;
    }
    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);
    return content;
}

void search_json(cJSON *json, const char *path, int client_fd) {
    char buffer[MAX_BUFFER];
    cJSON *current = json;

    char *token = strtok((char *)path, ".");
    while (token != NULL) {
        char *index_str = strchr(token, '[');
        if (index_str != NULL) {
            *index_str = '\0';
            int index = atoi(index_str + 1);
            cJSON *array = cJSON_GetObjectItemCaseSensitive(current, token);
            if (array == NULL || !cJSON_IsArray(array)) {
                snprintf(buffer, sizeof(buffer), "Path not found: %s\n", path);
                write(client_fd, buffer, strlen(buffer));
                return;
            }
            current = cJSON_GetArrayItem(array, index);
        } else {
            current = cJSON_GetObjectItemCaseSensitive(current, token);
        }

        if (current == NULL) {
            snprintf(buffer, sizeof(buffer), "Path not found: %s\n", path);
            write(client_fd, buffer, strlen(buffer));
            return;
        }
        token = strtok(NULL, ".");
    }

    char *result = cJSON_Print(current);
    if (result != NULL) {
        snprintf(buffer, sizeof(buffer), "Result: %s\n", result);
        free(result);
    } else {
        snprintf(buffer, sizeof(buffer), "No result found for the given path: %s\n", path);
    }
    write(client_fd, buffer, strlen(buffer));
}
void handle_search(int client_fd, const char *file_path, const char *search_path) {
    char buffer[MAX_BUFFER];
    char *json_string = read_file(file_path);
    if (!json_string) {
        snprintf(buffer, sizeof(buffer), "Error: Unable to read JSON file.\n");
        write(client_fd, buffer, strlen(buffer));
        return;
    }

    cJSON *json = cJSON_Parse(json_string);
    free(json_string);

    if (json == NULL) {
        snprintf(buffer, sizeof(buffer), "Error: Invalid JSON format.\n");
        write(client_fd, buffer, strlen(buffer));
        return;
    }

    search_json(json, search_path, client_fd);
    cJSON_Delete(json);
}

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    int is_unix_socket = *((int *)(arg + sizeof(int)));
    free(arg);

    char buffer[MAX_BUFFER];
    char file_path[MAX_BUFFER];
    char download_path[MAX_BUFFER];
    char authenticated_username[BUFFER_SIZE];
    memset(buffer, 0, MAX_BUFFER);
    memset(file_path, 0, MAX_BUFFER);
    memset(download_path, 0, MAX_BUFFER);

    while (1) {
        ssize_t bytes_read = read(client_fd, buffer, MAX_BUFFER - 1);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                printf("Client closed the connection\n");
            } else {
                perror("Read error");
            }
            break;
        }
        buffer[bytes_read] = '\0';

        printf("Debug: Received raw data: %s\n", buffer);
        char command[MAX_BUFFER], username[MAX_BUFFER], password[MAX_BUFFER];
        int role;
        sscanf(buffer, "%s %s %s", command, username, password);
        trim_whitespace(username);
        trim_whitespace(password);

        if (strcmp(command, "LOGIN") == 0) {
            if (db_check_user(username, password, &role)) {
                printf("User %s logged in as %s\n", username, role == 1 ? "admin" : "simple");
                if ((is_unix_socket && role == 1) || (!is_unix_socket && role == 0)) {
                    pthread_mutex_lock(&admin_mutex);
                    if (role == 1 && admin_connected) {
                        pthread_mutex_unlock(&admin_mutex);
                        snprintf(buffer, sizeof(buffer), "Admin already connected. Connection rejected.");
                        write(client_fd, buffer, strlen(buffer) + 1);
                        close(client_fd);
                        return NULL;
                    } else if (role == 1) {
                        admin_connected = 1;
                    }
                    pthread_mutex_unlock(&admin_mutex);

                    snprintf(buffer, sizeof(buffer), "Login successful");
                    add_user(username, client_fd);
                    char log_msg[MAX_BUFFER];
                    snprintf(log_msg, sizeof(log_msg), "User %.100s logged in as %s", username, is_unix_socket ? "admin" : "simple");
                    log_message(log_msg);
                    strcpy(authenticated_username, username);
                } else {
                    snprintf(buffer, sizeof(buffer), "Access denied");
                }
            } else {
                printf("Login failed for user %s\n", username);
                snprintf(buffer, sizeof(buffer), "Login failed");
            }
            if (write(client_fd, buffer, strlen(buffer) + 1) <= 0) {
                perror("Write error");
                break;
            }
        } else if (strcmp(command, "REGISTER") == 0) {
            if (!db_user_exists(username)) {
                db_add_user(username, password);
                snprintf(buffer, sizeof(buffer), "User registered successfully");
                char log_msg[MAX_BUFFER];
                snprintf(log_msg, sizeof(log_msg), "User %.100s registered as simple", username);
                log_message(log_msg);
            } else {
                snprintf(buffer, sizeof(buffer), "Username already exists");
            }
            if (write(client_fd, buffer, strlen(buffer) + 1) <= 0) {
                perror("Write error");
                break;
            }
        } else if (strcmp(command, "BLOCK_USER") == 0) {
            sscanf(buffer + strlen("BLOCK_USER "), "%255s", username);
            handle_block_user(client_fd, username);
        } else if (strcmp(command, "VIEW_ALL_USERS") == 0) {
            view_all_users(client_fd);
        } else if (strcmp(command, "UNBLOCK_USER") == 0) {
            sscanf(buffer + strlen("UNBLOCK_USER "), "%255s", username);
            handle_unblock_user(client_fd, username);
         } else if (strcmp(command, "UPLOAD_XML") == 0) {
            sscanf(buffer + strlen("UPLOAD_XML "), "%255s", file_path); // Extract file_path
            printf("Debug: username = %s\n", authenticated_username);
            handle_upload(client_fd, authenticated_username, file_path);
        } else if (strcmp(command, "DOWNLOAD_JSON") == 0) {
            sscanf(buffer + strlen("DOWNLOAD_JSON "), "%255s", download_path); // Extract download_path
            handle_download(client_fd, authenticated_username, download_path);
        }  else if (strcmp(command, "SEARCH_JSON") == 0) {
            char search_path[MAX_BUFFER];
            sscanf(buffer + strlen("SEARCH_JSON "), "%s %s", file_path, search_path);
            handle_search(client_fd, file_path, search_path);
        } else if (strcmp(command, "VIEW_USERS") == 0) {
            view_connected_users(buffer);
            if (write(client_fd, buffer, strlen(buffer) + 1) <= 0) {
                perror("Write error");
                break;
            }
        } else if (strcmp(command, "VIEW_LOGS") == 0) {
            char dir_path[MAX_BUFFER];
            sscanf(buffer + strlen("VIEW_LOGS "), "%s", dir_path);
            view_logs(client_fd, dir_path);
        } else if (strcmp(command, "DELETE_FILE") == 0) {
            char filename[MAX_BUFFER];
            sscanf(buffer + strlen("DELETE_FILE "), "%255s", filename);
            if (delete_file(filename)) {
                snprintf(buffer, sizeof(buffer), "File %.100s deleted successfully", filename);
                char log_msg[MAX_BUFFER];
                snprintf(log_msg, sizeof(log_msg), "File %.100s deleted", filename);
                log_message(log_msg);
            } else {
                snprintf(buffer, sizeof(buffer), "Failed to delete file %.100s", filename);
            }
            if (write(client_fd, buffer, strlen(buffer) + 1) <= 0) {
                perror("Write error");
                break;
            }
        } else if (strcmp(command, "LOGOUT") == 0) {
            snprintf(buffer, sizeof(buffer), "Logged out successfully");
            if (write(client_fd, buffer, strlen(buffer) + 1) <= 0) {
                perror("Write error");
                break;
            }
            remove_user(client_fd);
            if (is_unix_socket) {
                pthread_mutex_lock(&admin_mutex);
                admin_connected = 0;
                pthread_mutex_unlock(&admin_mutex);
            }
            close(client_fd);
            printf("User %s logged out\n", username);
            break;
        }
        memset(buffer, 0, MAX_BUFFER);
    }
    remove_user(client_fd);
    if (is_unix_socket) {
        pthread_mutex_lock(&admin_mutex);
        admin_connected = 0;
        pthread_mutex_unlock(&admin_mutex);
    }
    close(client_fd);
    printf("Connection closed and cleaned up\n");
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
                              MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL,
                              MHD_OPTION_END);
    if (NULL == daemon) {
        perror("Failed to start REST server");
        exit(-1);
    }

    printf("Server is running...\n");

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
    cleanup_resources();
    return 0;
}