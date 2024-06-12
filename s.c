void handle_upload(int client_fd, const char *authenticated_username, const char *client_file_path) {
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
    char log_msg[2048]; // Increased buffer size
    snprintf(log_msg, sizeof(log_msg), "User %s converted file %s to %s", authenticated_username, full_path, json_file_path);
    log_message(log_msg);
    // Store the converted JSON filename in the global variable

    snprintf(converted_json_filename, sizeof(converted_json_filename), "converted_%s.json", file_name_without_ext);

    snprintf(buffer, sizeof(buffer), "Success: File uploaded and converted successfully.\n");
    write(client_fd, buffer, strlen(buffer));
    fsync(client_fd);
    printf("Debug: File uploaded and converted successfully.\n");
    snprintf(log_msg, sizeof(log_msg), "User %s uploaded file %s", authenticated_username, client_file_path);
    log_message(log_msg);
}