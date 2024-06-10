#ifndef REST_HANDLERS_H
#define REST_HANDLERS_H

#include <microhttpd.h>
#include <stdio.h>
// #include "rest_handlers.h"
#include "db.h"
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>


#define BUFFER_SIZE 256
#define UPLOAD_BUFFER_SIZE 1024

struct UploadInfo {
    char buffer[UPLOAD_BUFFER_SIZE];
    size_t buffer_size;
    FILE *fp;
};

struct ConnectionInfo {
    struct MHD_PostProcessor *pp;
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
};

void add_cors_headers(struct MHD_Response *response);

int upload_xml_rest(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                    const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

int download_json_rest(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                       const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

int check_user_rest(void *cls, struct MHD_Connection *connection,
                    const char *url, const char *method, const char *version,
                    const char *upload_data, size_t *upload_data_size, void **con_cls);

int add_user_rest(void *cls, struct MHD_Connection *connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t *upload_data_size, void **con_cls);

int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key, const char *filename,
                 const char *content_type, const char *transfer_encoding, const char *data, uint64_t off, size_t size);

void request_completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);

void log_message(const char *message);

 void trim_whitespace(char *str);


void add_cors_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
}

int upload_xml_rest(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                    const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    struct UploadInfo *upload_info = *con_cls;
    if (NULL == upload_info) {
        upload_info = malloc(sizeof(struct UploadInfo));
        if (NULL == upload_info)
            return MHD_NO;
        upload_info->buffer_size = 0;
        upload_info->fp = fopen("uploaded.xml", "wb");  // Ensure FILE * is used
        if (NULL == upload_info->fp) {
            free(upload_info);
            return MHD_NO;
        }
        *con_cls = upload_info;
        return MHD_YES;
    }

    if (0 != *upload_data_size) {
        fwrite(upload_data, 1, *upload_data_size, upload_info->fp);  // Ensure FILE * is used
        *upload_data_size = 0;
        return MHD_YES;
    } else {
        fclose(upload_info->fp);  // Ensure FILE * is used

        // Convert XML to JSON
        XMLDocument doc2;
        if (XMLDocument_load(&doc2, "uploaded.xml")) {
            cJSON *json = XMLDocumentToJSON(&doc2);
            SaveJSONToFile("converted.json", json);
            cJSON_Delete(json);
            XMLDocument_free(&doc2);
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

int download_json_rest(void *cls, struct MHD_Connection *connection, const char *url, const char *method,
                       const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    FILE *fp = fopen("converted.json", "rb");  // Ensure FILE * is used
    if (!fp) {
        return MHD_NO;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);  // Ensure FILE * is used

    struct MHD_Response *response = MHD_create_response_from_buffer(file_size, file_data, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Disposition", "attachment; filename=\"converted.json\"");
    add_cors_headers(response);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

int check_user_rest(void *cls, struct MHD_Connection *connection,
                    const char *url, const char *method, const char *version,
                    const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    const char *username = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "username");
    const char *password = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "password");

    if (username == NULL || password == NULL) {
        const char *error = "Username or password not provided";
        struct MHD_Response *response = MHD_create_response_from_buffer(strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
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
            add_cors_headers(response);
            int ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
            MHD_destroy_response(response);
            return ret;
        } else {
            const char *response_msg = "user exists";
            struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_msg), (void *)response_msg, MHD_RESPMEM_PERSISTENT);
            add_cors_headers(response);
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
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
}

int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key, const char *filename,
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

int add_user_rest(void *cls, struct MHD_Connection *connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        add_cors_headers(response);
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
        add_cors_headers(response);
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
        add_cors_headers(response);
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
        add_cors_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_CONFLICT, response);
        MHD_destroy_response(response);
        printf("Debug: Username already exists\n");
        return ret;
    }
}

void request_completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
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

void log_message(const char *message) {
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


#endif // REST_HANDLERS_H
