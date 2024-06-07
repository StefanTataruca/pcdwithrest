#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 256

void trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    *(end + 1) = '\0';
}

void show_action_menu() {
    printf("1. Login\n");
    printf("2. Register\n");
    printf("3. Exit\n");
    fflush(stdout); // Flush after writing to stdout
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

void login_via_inet() {
    int socket_fd;
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    socket_fd = connect_to_server();
    if (socket_fd == -1) return;

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    trim_whitespace(username);  // Remove whitespace and newline

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    trim_whitespace(password);  // Remove whitespace and newline

    snprintf(buffer, BUFFER_SIZE, "LOGIN %.100s %.100s", username, password);
    printf("Debug: Sending buffer: %s\n", buffer);
    write(socket_fd, buffer, strlen(buffer));

    memset(response, 0, sizeof(response));  // Clear the response buffer before reading
    read(socket_fd, response, BUFFER_SIZE);
    printf("Debug: Received: %s\n", response);

    if (strcmp(response, "Login successful") == 0) {
        printf("Login successful. Exiting...\n");
        close(socket_fd);
        exit(0);
    } else {
        printf("Login failed. Try again.\n");
    }

    close(socket_fd);
}

void register_via_inet() {
    int socket_fd;
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    socket_fd = connect_to_server();
    if (socket_fd == -1) return;

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
    printf("Received: %s\n", response);
    fflush(stdout);

    close(socket_fd);
    show_action_menu(); // Show menu again after registration
}

int main() {
    char choice[BUFFER_SIZE];

    show_action_menu();
    while (1) {
        printf("Enter choice: ");
        fgets(choice, BUFFER_SIZE, stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (strcmp(choice, "1") == 0) {
            login_via_inet();
        } else if (strcmp(choice, "2") == 0) {
            register_via_inet();
        } else if (strcmp(choice, "3") == 0) {
            exit(0);
        } else {
            printf("Invalid choice. Please try again.\n");
            fflush(stdout);
        }
    }
    return 0;
}
