#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "rest_client.h"
#include "db.h"
#include <sqlite3.h>

#define BUFFER_SIZE 256 // Use the same buffer size

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char *response = (char *)userp;
    if (strlen(response) + realsize >= BUFFER_SIZE - 1) {
        return 0; // Buffer is too small
    }
    strncat(response, (char *)contents, realsize);
    return realsize;
}

void make_rest_request(const char *url, char *response, const char *username, const char *password) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        printf("Making REST request to URL: %s\n", url);
        char full_url[256];
        snprintf(full_url, sizeof(full_url), "%s?username=%s&password=%s", url, username, password);
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

int rest_check_user(const char *username, const char *password) {
    char response[BUFFER_SIZE] = {0};
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:8888/check_user?username=%s&password=%s", username, password);
    make_rest_request(url, response, NULL, NULL);
    printf("rest_check_user response: %s\n", response);

    // Check if the user exists in the database
    if (strstr(response, "user exists") != NULL) {
        return 1;
    } else {
        return 0;
    }
}

void rest_add_user(const char *username, const char *password) {
    char response[BUFFER_SIZE] = {0};
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:8888/add_user");
    make_rest_request(url, response, username, password);
    printf("rest_add_user response: %s\n", response);
}

int rest_login(const char *username, const char *password) {
    return rest_check_user(username, password);
}

int rest_register(const char *username, const char *password) {
    // Send a request to the server to check if the user exists
    char response[BUFFER_SIZE] = {0};
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:8888/check_user?username=%s", username);
    make_rest_request(url, response, NULL, NULL);

    if (strstr(response, "user exists") != NULL) {
        // User already exists, display error message
        printf("User already exists\n");
        return 0;
    }

    // User doesn't exist, send a request to create a new account
    snprintf(url, sizeof(url), "http://localhost:8888/add_user");
    make_rest_request(url, response, username, password);

    if (strstr(response, "User added successfully") != NULL) {
        // Account created successfully
        printf("Account created successfully\n");
        return 1;
    }

    printf("Account creation failed\n");
    return 0; // Account creation failed
}
