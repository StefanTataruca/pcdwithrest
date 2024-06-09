#ifndef REST_CLIENT_H
#define REST_CLIENT_H

#include <microhttpd.h>

#define BUFFER_SIZE 256 // Ensure consistent buffer size
#define UPLOAD_BUFFER_SIZE 1024

struct UploadInfo {
    char buffer[UPLOAD_BUFFER_SIZE];
    size_t buffer_size;
    FILE *fp;  // This should be FILE *, not int *
};

struct ConnectionInfo {
    struct MHD_PostProcessor *pp;
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
};

// Remove static function definitions
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

#endif // REST_CLIENT_H
