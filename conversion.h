#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdio.h>
#include "json.h"

void convert_xml_to_json(const char *xml_file, const char *json_file);



void convert_xml_to_json(const char *xml_file, const char *json_file) {
    XMLDocument doc1;
    if (XMLDocument_load(&doc1, xml_file)) {
        cJSON *json = XMLDocumentToJSON(&doc1);
        SaveJSONToFile(json_file, json);
        cJSON_Delete(json);
        XMLDocument_free(&doc1);
    }
}

#endif // CONVERSION_H
