#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>
#include <libgen.h>
#include <pthread.h> // Adaugă include-ul pentru pthread
#include <stdint.h>
#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 256

void trim_whitespace(char *str);
int is_xml_file(const char *filename);
void show_action_menu();
int connect_to_server();
void login(int socket_fd);
void register_user();
void upload_xml(int socket_fd);
void download_json(int socket_fd, const char *download_path);
void listen_for_messages(int socket_fd);

void trim_whitespace(char *str) {
    char *end;

    while (isspace((unsigned char)*str)) str++;

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    *(end + 1) = '\0';
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
    fgets(username, BUFFER_SIZE / 2, stdin);
    trim_whitespace(username);

    printf("Password: ");
    fgets(password, BUFFER_SIZE / 2, stdin);
    trim_whitespace(password);

    snprintf(buffer, BUFFER_SIZE, "REGISTER %.100s %.100s", username, password);
    write(socket_fd, buffer, strlen(buffer));
    memset(response, 0, sizeof(response));

    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    close(socket_fd);
}

void upload_xml(int socket_fd) {
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    char file_path[BUFFER_SIZE];
    char download_path[BUFFER_SIZE];
    FILE *file;
    struct stat st;

    printf("Enter the path of the XML file to upload: ");
    fgets(file_path, sizeof(file_path), stdin);
    trim_whitespace(file_path);

    if (!is_xml_file(file_path)) {
        printf("The file is not an XML file. Please try again.\n");
        return;
    }

    if (stat(file_path, &st) != 0) {
        perror("File not found");
        return;
    }

    file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    snprintf(buffer, sizeof(buffer), "UPLOAD_XML %.200s", file_path); // Limitează dimensiunea datelor

    write(socket_fd, buffer, strlen(buffer));
    memset(buffer, 0, BUFFER_SIZE);

    while (fread(buffer, 1, BUFFER_SIZE, file) > 0) {
        write(socket_fd, buffer, BUFFER_SIZE);
        memset(buffer, 0, BUFFER_SIZE);
    }

    fclose(file);
    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    if (strcmp(response, "File uploaded and converted successfully.") == 0) {
        printf("Enter the path where you want to save the downloaded JSON file: ");
        fgets(download_path, sizeof(download_path), stdin);
        trim_whitespace(download_path);

        snprintf(buffer, sizeof(buffer), "DOWNLOAD_JSON %.200s", download_path); // Limitează dimensiunea datelor
        write(socket_fd, buffer, strlen(buffer));
        memset(buffer, 0, BUFFER_SIZE);

        read(socket_fd, response, BUFFER_SIZE);
        if (strcmp(response, "DOWNLOAD_READY") == 0) {
            download_json(socket_fd, download_path);
        } else {
            printf("Failed to download JSON file.\n");
        }
    }
}

void download_json(int socket_fd, const char *download_path) {
    char buffer[BUFFER_SIZE];
    char file_path[BUFFER_SIZE];
    FILE *file;

    snprintf(buffer, BUFFER_SIZE, "DOWNLOAD_JSON");
    write(socket_fd, buffer, strlen(buffer));
    memset(buffer, 0, BUFFER_SIZE);

    read(socket_fd, buffer, BUFFER_SIZE);
    if (strcmp(buffer, "DOWNLOAD_READY") != 0) {
        printf("Failed to download JSON file.\n");
        return;
    }

    snprintf(file_path, sizeof(file_path), "%s/converted.json", download_path);

    file = fopen(file_path, "wb");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }

    while (read(socket_fd, buffer, BUFFER_SIZE) > 0) {
        fwrite(buffer, 1, BUFFER_SIZE, file);
        memset(buffer, 0, BUFFER_SIZE);
    }

    fclose(file);
    printf("File downloaded successfully to %s.\n", file_path);
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
                printf("Enter the path where you want to save the downloaded JSON file: ");
                char download_path[BUFFER_SIZE];
                fgets(download_path, sizeof(download_path), stdin);
                trim_whitespace(download_path);
                download_json(socket_fd, download_path);
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
