#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json.h"
#include "lxml.h"

int convert_xml_to_json(const char *xml_file, const char *json_file) {
    XMLDocument doc;
    if (!XMLDocument_load(&doc, xml_file)) {
        fprintf(stderr, "Failed to load XML file: %s\n", xml_file);
        return 1;
    }

    cJSON *json = XMLDocumentToJSON(&doc);
    if (!json) {
        fprintf(stderr, "Failed to convert XML to JSON\n");
        XMLDocument_free(&doc);
        return 1;
    }

    FILE *fp = fopen(json_file, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open JSON file for writing: %s\n", json_file);
        cJSON_Delete(json);
        XMLDocument_free(&doc);
        return 1;
    }

    char *json_string = cJSON_Print(json);
    if (json_string == NULL) {
        fprintf(stderr, "Failed to print JSON object\n");
        fclose(fp);
        cJSON_Delete(json);
        XMLDocument_free(&doc);
        return 1;
    }

    fprintf(fp, "%s", json_string);
    fclose(fp);

    free(json_string);
    cJSON_Delete(json);
    XMLDocument_free(&doc);

    return 0;
}


#endif // CONVERSION_H
