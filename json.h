#ifndef JSON_H
#define JSON_H

#include <cjson/cJSON.h>
#include "lxml.h"
#include <ctype.h>
#include <ctype.h>

char *remove_all_whitespaces_new(const char *str) {
    int new_len = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isspace(str[i])) {
            new_len++; /* Increment the value if the character is not a white space */
        }
    }

    char *new_str = (char *)malloc(new_len + 1); /* Allocate memory for the new string */ 
    
    /* If the memory could not be allocated, return null*/
    if (new_str == NULL) {
        return NULL;
    }

    int j = 0;
    /* Iterrate through the string and add each character that is not a white space to the new string*/
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isspace(str[i])) {
            new_str[j++] = str[i];
        }
    }
    new_str[j] = '\0'; /* Mark the ending of the string */

    return new_str; /* Return the new string */
}

/* Funciton will get a list of attributes for a node and a cJSON object noed */
cJSON* XMLAttributesToJSON(XMLAttributeList* attributes, cJSON* jsonAttributes) {
    /* Iterrate though all attributes of the current node */
    for (int i = 0; i < attributes->size; ++i) {
        XMLAttribute* attribute = &attributes->data[i]; /* Get the attribute data*/
        int attr_key_len = strlen(attribute->key); /* Get the length of the attribute key */
        char* attr_key = (char*)malloc(attr_key_len + 2); /* Allocate memory for the new key */

        /* If the memory could not be allocated, print an error message and exit */
        if (!attr_key) {
            fprintf(stderr, "Error! Could not allocate memory for attribute key in the json parser!\n");
            exit(EXIT_FAILURE);
        }

        strcpy(attr_key, "_"); /* Add an underscore to the new key */
        strcat(attr_key, attribute->key); /* Add the previous key to the new one */

        cJSON_AddStringToObject(jsonAttributes, attr_key, attribute->value); /* Add the new key and it's value to the cJSON object */
        free(attr_key); /* free the memory allocated to the new key*/
    }
    return jsonAttributes; /* Return the cJSON object */
}

cJSON* XMLNodeToJSON(XMLNode* node) {
    /* Check if the node has no children but has an inner text */
    if (node->children.size == 0 && node->inner_text) {
        if (node->attributes.size > 0) { /* Check for node attributes */
            cJSON* jsonNode = cJSON_CreateObject(); /* Create a new cJSON object */
            cJSON_AddStringToObject(jsonNode, "__text", node->inner_text); /* Add the inner text of the node */
            XMLAttributesToJSON(&node->attributes, jsonNode); /* Add the attributes of the node */
            return jsonNode; /* Return the cJSON object */
        }
        /* If the node has no attributes, add the inner text of the node  */
        return cJSON_CreateString(node->inner_text); /* Return the cJSON object */
    }

    /* Case where the node has children */
    cJSON* jsonNode = cJSON_CreateObject(); /* Create a new cJSON object */
    
    if (node->inner_text) { /* If the node has inner text, remove possible white spaces and new lines */
        char* text = remove_all_whitespaces_new(node->inner_text);
        if (strlen(text) > 0)
            cJSON_AddStringToObject(jsonNode, "__text", text); /* Add the inner text to the object */
    }
    
    /* Iterrate through the children list of the current node */
    for (int i = 0; i < node->children.size; ++i) {
        XMLNode* child = node->children.data[i]; 
        cJSON* childJSON = XMLNodeToJSON(child);
        cJSON* existing = cJSON_GetObjectItem(jsonNode, child->tag);

        if (existing) {
            if (!cJSON_IsArray(existing)) {
                cJSON* array = cJSON_CreateArray();
                cJSON_AddItemToArray(array, cJSON_Duplicate(existing, 1));
                cJSON_ReplaceItemInObject(jsonNode, child->tag, array);
                existing = array;
            }
            cJSON_AddItemToArray(existing, childJSON);
        } else {
            cJSON_AddItemToObject(jsonNode, child->tag, childJSON);
        }
    }

    return jsonNode;
}

cJSON* XMLDocumentToJSON(XMLDocument* document) {
    cJSON* jsonDoc = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonDoc, "version", document->version);
    cJSON_AddStringToObject(jsonDoc, "encoding", document->encoding);

    /* Check for duplicates root tag names, return null if they exist */
    if (document->root->children.size > 0) {
        for (int i = 0; i < document->root->children.size; i++) {
            for (int j = i + 1; j < document->root->children.size; j++) {
                if (!strcmp(document->root->children.data[i]->tag, document->root->children.data[j]->tag))
                    return jsonDoc;
            }
        }


        for (int i = 0; i < document->root->children.size; i++) {
            XMLNode* root_child = document->root->children.data[i];
            cJSON_AddItemToObject(jsonDoc, root_child->tag, XMLNodeToJSON(root_child));
        }
    }

    return jsonDoc;
}

void SaveJSONToFile(const char* filename, cJSON* json) {
    char* jsonString = cJSON_Print(json);
    FILE* file = fopen(filename, "w");
    if (file) {
        fputs(jsonString, file);
        fclose(file);
    }
    cJSON_free(jsonString);
}

void convertJSONtoXML(cJSON *json, XMLNode *xmlNode) {
    switch (json->type) {
        case cJSON_Object: {
            cJSON *child = json->child;
            while (child) {
                XMLNode *childXmlNode = XMLNode_new(xmlNode);
                childXmlNode->tag = strdup(child->string);
                convertJSONtoXML(child, childXmlNode);
                child = child->next;
            }
            break;
        }
        case cJSON_Array: {
            cJSON *child = json->child;
            while (child) {
                XMLNode *childXmlNode = XMLNode_new(xmlNode);
                childXmlNode->tag = strdup("item"); // Assuming array items are wrapped in <item> tags
                convertJSONtoXML(child, childXmlNode);
                child = child->next;
            }
            break;
        }
        case cJSON_String:
            xmlNode->inner_text = strdup(json->valuestring);
            break;
        // Add handling for other data types as needed
        default:
            break;
    }
}

#endif
