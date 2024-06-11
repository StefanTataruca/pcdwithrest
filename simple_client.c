#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>
#include <libgen.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1035
#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"
#define MAX_FILE_PATH 512

void trim_whitespace(char *str);
void trim_trailing_slash(char *str);
int is_xml_file(const char *filename);
void show_action_menu();
int connect_to_server();
void login(int socket_fd);
void register_user();
void upload_xml(int socket_fd);
void download_json(int socket_fd, const char *download_dir);
void listen_for_messages(int socket_fd);

void trim_whitespace(char *str) {
    char *end;

    while (isspace((unsigned char)*str)) str++;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';
}

void trim_trailing_slash(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '/') {
        str[len - 1] = '\0';
    }
}

int is_xml_file(const char *filename) {
    const char *dot = strrchr(filename, '.');
    return dot && strcmp(dot, ".xml") == 0;
}

void show_action_menu() {
    printf("1. Login\n");
    printf("2. Register\n");
    printf("3. Upload XML file\n");
    printf("4. Download converted JSON file\n");
    printf("5. Exit\n");
    fflush(stdout);
}

int connect_to_server() {
    int socket_fd;
    struct sockaddr_in server_addr;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("Socket error");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connect error");
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

void login(int socket_fd) {
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    trim_whitespace(username);

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    trim_whitespace(password);

    snprintf(buffer, BUFFER_SIZE, "LOGIN %.100s %.100s", username, password);
    write(socket_fd, buffer, strlen(buffer));

    memset(response, 0, sizeof(response));
    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    if (strcmp(response, "Login successful") != 0) {
        printf("Login failed. Try again.\n");
        close(socket_fd);
        exit(0);
    }
}

void register_user() {
    int socket_fd = connect_to_server();
    if (socket_fd == -1) return;

    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    printf("Register with your username: ");
    fgets(username, sizeof(username), stdin);
    trim_whitespace(username);

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    trim_whitespace(password);

    snprintf(buffer, BUFFER_SIZE, "REGISTER %.100s %.100s", username, password);
    write(socket_fd, buffer, strlen(buffer));
    memset(response, 0, sizeof(response));

    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    close(socket_fd);
}

int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    return 0;
}

void upload_xml(int socket_fd) {
    char buffer[BUFFER_SIZE];
    char file_path[MAX_FILE_PATH];
    FILE *file;
    ssize_t bytes_read;

    printf("Enter the path of the XML file to upload: ");
    fgets(file_path, sizeof(file_path), stdin);
    trim_whitespace(file_path);

    if (!is_xml_file(file_path)) {
        printf("The file is not an XML file. Please try again.\n");
        return;
    }

    file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    snprintf(buffer, BUFFER_SIZE, "UPLOAD_XML %.1023s", file_path);
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Path sent to server: %s\n", buffer);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        printf("Debug: Read %zd bytes from file\n", bytes_read);
        if (write(socket_fd, buffer, bytes_read) != bytes_read) {
            perror("Failed to send file to server");
            fclose(file);
            return;
        }
        memset(buffer, 0, BUFFER_SIZE);
    }

    fclose(file);

    snprintf(buffer, BUFFER_SIZE, "END_OF_FILE");
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Finished sending file. Waiting for server response...\n");

    // Wait for response from server
    ssize_t bytes_received = read(socket_fd, buffer, BUFFER_SIZE);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Debug: Response from server after upload: %s\n", buffer);
        printf("%s\n", buffer);
    } else {
        perror("Debug: No response from server or error reading response");
    }
}

void download_json(int socket_fd, const char *download_dir) {
    char buffer[BUFFER_SIZE];
    FILE *file;
    ssize_t bytes_received;
    char download_path[MAX_FILE_PATH * 2];
    char directory[MAX_FILE_PATH];

    strncpy(directory, download_dir, MAX_FILE_PATH);
    trim_trailing_slash(directory);

    snprintf(buffer, BUFFER_SIZE, "DOWNLOAD_JSON %s", directory);
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Path sent to server: %s\n", buffer);

    // Assume the server sends the filename first
    bytes_received = read(socket_fd, buffer, BUFFER_SIZE);
    if (bytes_received <= 0) {
        perror("Failed to receive filename from server");
        return;
    }
    buffer[bytes_received] = '\0'; // Null-terminate the received data
    printf("Debug: Filename received from server: %s\n", buffer);

    int len = snprintf(download_path, sizeof(download_path), "%s/%s", directory, buffer);
    if (len >= sizeof(download_path)) {
        perror("Failed to create download path");
        return;
    }

    file = fopen(download_path, "wb");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }

    while ((bytes_received = read(socket_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_received] = '\0'; // Null-terminate the buffer to safely use strstr
        printf("Debug: Received data chunk: %s\n", buffer); // Debug print

        char *eof_pos = strstr(buffer, "END_OF_FILE");
        if (eof_pos != NULL) {
            fwrite(buffer, 1, eof_pos - buffer, file);
            printf("Debug: Detected end of file marker\n");
            break;
        } else {
            fwrite(buffer, 1, bytes_received, file);
        }
    }

    fclose(file);
    printf("Debug: Finished receiving file. File saved to %s.\n", download_path);

    if (bytes_received == 0) {
        printf("Debug: Server closed connection.\n");
    } else if (bytes_received < 0) {
        perror("Error reading from server");
    } else {
        printf("Debug: End of file received.\n");
    }
}

void listen_for_messages(int socket_fd) {
    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            printf("Connection closed by server.\n");
            close(socket_fd);
            exit(0);
        }
        buffer[bytes_read] = '\0';

        if (strcmp(buffer, "DISCONNECT") == 0) {
            printf("You have been disconnected by the server.\n");
            close(socket_fd);
            exit(0);
        }

        // Handle other messages from server if needed
    }
}

int main() {
    char choice[BUFFER_SIZE];
    int socket_fd = -1;
    pthread_t listener_thread;

    while (1) {
        show_action_menu();
        printf("Enter choice: ");
        fgets(choice, BUFFER_SIZE, stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (strcmp(choice, "1") == 0) {
            if (socket_fd != -1) close(socket_fd);
            socket_fd = connect_to_server();
            if (socket_fd != -1) {
                login(socket_fd);
                pthread_create(&listener_thread, NULL, (void *(*)(void *))listen_for_messages, (void *)(intptr_t)socket_fd);
                pthread_detach(listener_thread);
            }
        } else if (strcmp(choice, "2") == 0) {
            register_user();
        } else if (strcmp(choice, "3") == 0) {
            if (socket_fd != -1) upload_xml(socket_fd);
            else printf("You need to login first.\n");
        } else if (strcmp(choice, "4") == 0) {
            if (socket_fd != -1) {
                printf("Enter the directory path where you want to save the downloaded JSON file: ");
                char download_dir[MAX_FILE_PATH];
                fgets(download_dir, sizeof(download_dir), stdin);
                trim_whitespace(download_dir);
                download_json(socket_fd, download_dir);
            } else printf("You need to login first.\n");
        } else if (strcmp(choice, "5") == 0) {
            if (socket_fd != -1) close(socket_fd);
            exit(0);
        } else {
            printf("Invalid choice. Please try again.\n");
            fflush(stdout);
        }
    }
    return 0;
}
