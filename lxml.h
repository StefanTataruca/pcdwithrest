#ifndef LITTLE_XML_H
#define LITTLE_XML_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

/* 
    Definitions 
*/

#ifndef TRUE
    #define TRUE 1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

enum _TagType /* type used to mention if a node is inline <tag /> or a usual node <tag></tag> */
{
    TAG_START, 
    TAG_INLINE
};
typedef enum _TagType TagType;

/* Since XML nodes can have key-value type attributes inside the opening tag, we have to parse them too */
struct _XMLAttribute
{
    char* key; /* Key of the attribute */
    char* value; /* The value of the attribute */
};
typedef struct _XMLAttribute XMLAttribute;

/* A tag cah have multiple attributes, so we will use a list to store them*/
struct _XMLAttributeList
{
    int heap_size; /* Size of the memory allocated for the list */
    int size; /* Number of attributes stored in the list */
    XMLAttribute* data; /* Attribute */
};
typedef struct _XMLAttributeList XMLAttributeList;

/* To store all the nodes, implement a node list */
struct _XMLNodeList
{
    int heap_size; /* Size of the memory allocated for the list */
    int size; /* Number of elements stored in the list */
    struct _XMLNode** data; /* Elements */
};
typedef struct _XMLNodeList XMLNodeList;

/* The node will hold the information about each xml node */
struct _XMLNode
{
    char* tag; /* Tag name */
    char* inner_text; /* The text between the tags */
    struct _XMLNode* parent; /* A pointer to the parent node for iterration */
    XMLAttributeList attributes; /* The list of attributes */
    XMLNodeList children; /* List of children of the node */
};
typedef struct _XMLNode XMLNode;

/* General information about the xml file */
struct _XMLDocument
{
    XMLNode* root; /* First node in the list <?xml> */
    char* version; /* XML version ex: 1.0*/
    char* encoding; /* Enocoding type of the file ex: UTF-8*/
};
typedef struct _XMLDocument XMLDocument;

/* Functions definition */

/* Definitions for each XMLDocument structure function */
int XMLDocument_load(XMLDocument* doc, const char* path); /* Function used to initialize the XMLDocument */
int XMLDocument_write(XMLDocument* doc, const char* path, int indent); /* Function used to create a new XML file */
void XMLDocument_free(XMLDocument* doc); /* Function used to free the memroy allocated for the XMLDocument object */

/* Definitions for each XMLNode structure function */
XMLNode* XMLNode_new(XMLNode* parent); /* Function that creates a new XMLNode */
void XMLNode_free(XMLNode* node); /* Function used to free the memory allocated for a XMLNode */
XMLNode* XMLNode_child(XMLNode* parent, int index); /* Function that returns a XMLNode at a specific `index` */
XMLNodeList* XMLNode_children(XMLNode* parent, const char* tag); /* Function used to return the list of children of a node */
char* XMLNode_attr_val(XMLNode* node, char* key); /* Function used to return the attribute of a key from a XMLNode */
XMLAttribute* XMLNode_attr(XMLNode* node, char* key); /* Function used to return a XMLAttribute of a node that has a specific `key` */

/* Definitions for each XMLAttribute structure function */
void XMLAttribute_free(XMLAttribute* attr); /* Function used to free the memroy allocated to a node attribute */

/* Definitions for each XMLAttributeList structure function */
void XMLAttributeList_init(XMLAttributeList* list); /* Function used to initialize the list of attributes of a XMLNode */
void XMLAttributeList_add(XMLAttributeList* list, XMLAttribute* attr); /* Function used to add an attribute to a node attribute list */

/* Definitions for each XMLNodeList structure function */
void XMLNodeList_init(XMLNodeList* list); /* Function used to initialize a list of XMLNodes */
void XMLNodeList_add(XMLNodeList* list, struct _XMLNode* node); /* Function used to add a XMLNode to a XMLNodeList */
struct _XMLNode* XMLNodeList_at(XMLNodeList* list, int index); /* Function used to get a XMLNode from a XMLNodeList */
void XMLNodeList_free(XMLNodeList* list); /* Function used to free the memory allocated to a XMLNodeList */


static TagType parse_attributes(char* buf, int* i, char* lex, int* lexi, XMLNode* curr_node);
int ends_with(const char* haystack, const char* needle);
static void node_out(FILE* file, XMLNode* node, int indent, int times);
/*
    Functions implementation 
*/

int XMLDocument_load(XMLDocument* doc, const char* path) {
    FILE* file = fopen(path, "r"); /* Open an xml file in reading mode*/
    if (!file) { /* If the file could not be oppened, print an error message and exit */
        fprintf(stderr, "Error! Could not load file from '%s'\n", path);
        return FALSE;
    }

    fseek(file, 0, SEEK_END); /* Search untill file ending */
    int size = ftell(file); /* Get the file size */
    fseek(file, 0, SEEK_SET); /* Reset the position to the beginning of the file */

    fprintf(stdout, "File size: %ld\n", ftell(file));

    char* buffer = (char*) malloc(sizeof(char) * size + 1); /* Allocate the memory for the buffer with the file size */
    
    if (!buffer) { /* If the momory could not be allocated to the buffer, print an error message and exit */
        fprintf(stderr, "Error! Could not allocate memory to the buffer!\n");
        return FALSE;
    }
    
    /* Read the file in the buffer */
    if (!fread(buffer, 1, size, file)) { /* If the data could not be read from the file into the buffer, print an error message and exit*/
        fprintf(stderr, "Error! Could not read file data into the buffer!\n");
        exit(EXIT_FAILURE);
    } 

    fclose(file); /* Close the file after reading */
    buffer[size] = '\0'; /* Set the ending of the buffer */

    doc->root = XMLNode_new(NULL); /* Initialize the document root node */

    char file_lexical[256]; /* Declare a character array that will hold the inner text of the buffer */
    int lex = 0, i = 0; /* Set the buffer index and the file_lexical index to 0*/

    XMLNode* curr_node = doc->root; /* Create the current node */
    int in_text = 0;

    while (buffer[i] != '\0') /* Reaf untill the end of the buffer */
    {
        if (buffer[i] == '<') { /* If the character from the buffer is the beginning of a tag */
            file_lexical[lex] = '\0'; /* Set the file_lexical string end point */

            /* Check if the text is outside of the tag */
            if (in_text && lex > 0) {
                if (!curr_node) {  /* If the node is null, the text was outside the tags.*/
                    fprintf(stderr, "Error! Text could not be outside of document\n"); /* Print an error message and exit */
                    return FALSE;
                }

                /* Check for data inside the inner text of the current node */
                if (curr_node->inner_text) {
                    char* new_text = (char*) malloc(strlen(curr_node->inner_text) + strlen(file_lexical) + 1); /* Allocate the memory for the text */
                    strcpy(new_text, curr_node->inner_text); /* Coppy the text from the inner_text of the node to the new text */
                    strcat(new_text, file_lexical); /* Add the text stored in the file_lexical to the new text */
                    free(curr_node->inner_text); /* Free the memory allocated to the new text*/
                    curr_node->inner_text = new_text; /* Set the inner text of the current node to the new text*/
                } else { /* If the inner text was null, set the inner text to the file_lexical string */
                    curr_node->inner_text = strdup(file_lexical);
                }

                lex = 0; /* Reset the file_lexical index */
            }

            in_text = 0; /* Reset the in_text value */

            /* Check for the closing tag */
            /* If the next character after `<` is a back slash, then we found the closing tag */
            if (buffer[i + 1] == '/') {
                i += 2; /* Get thte first letter after the closing tag `</`*/
                while (buffer[i] != '>') /* Read untill the end of the closing tag `>` */
                    file_lexical[lex++] = buffer[i++]; /* Store each character in the file lexical */
                file_lexical[lex] = '\0'; /* Set the ending of the file lexical */

                if (!curr_node) { /* If the current node is null, we are at the root of the document. */
                    fprintf(stderr, "Error! Already at the root of the document\n"); /* Print an error message and exit*/
                    return FALSE;
                }

                if (strcmp(curr_node->tag, file_lexical)) { /* Check if the beginning and closing tags are different */
                    fprintf(stderr, "Error! Mismatched tags (%s != %s)\n", curr_node->tag, file_lexical); /* Print an error message and exit */ 
                    return FALSE;
                }

                curr_node = curr_node->parent; /* Move to the parent node */
                i++; /* Increment the buffer index */
                continue; /* Move to the next iterration */
            }

            /* Check for comments  */
            if (buffer[i + 1] == '!') { /* If the text starts with `<` and is followed by the `!` character get each character untill `>` */
                while (buffer[i] != ' ' && buffer[i] != '>')
                    file_lexical[lex++] = buffer[i++]; /* Store the characters in the file_lexical */
                file_lexical[lex] = '\0'; /* Set the ending of the file lexical string */

                /* If the string is equal to <!--, we found the start of the comment */
                if (!strcmp(file_lexical, "<!--")) {
                    file_lexical[lex] = '\0'; /* Set the ending of the file_lexical string */
                    while (!ends_with(file_lexical, "-->")) { /* Read each character untill the comment ending */
                        file_lexical[lex++] = buffer[i++]; /* Store the characters in the file_lexical string */
                        file_lexical[lex] = '\0'; /* Set the ending of the file_lexical string */
                    }
                    continue; /* Move to the next iterration */
                }
            }

            /* Check for the declaration tags */
            if (buffer[i + 1] == '?') {
                while (buffer[i] != ' ' && buffer[i] != '>') /* Get each character untill `>` */
                    file_lexical[lex++] = buffer[i++]; /* Store the character to the file_lexical string */
                file_lexical[lex] = '\0'; /* Set the ending of the file_lexical string */

                /* Check for XML declaration */
                if (!strcmp(file_lexical, "<?xml")) {
                    lex = 0; /* Reset the file_lexical index */
                    XMLNode* desc = XMLNode_new(NULL); /* Create a new node that will keep the declaration data */
                    parse_attributes(buffer, &i, file_lexical, &lex, desc);

                    doc->version = XMLNode_attr_val(desc, "version"); /* Get the xml version */
                    doc->encoding = XMLNode_attr_val(desc, "encoding"); /* Get the xml encoding type */
                    continue; /* Move to the next iterration */
                }
            }

            /* Set the current node */
            curr_node = XMLNode_new(curr_node);

            i++; /* Increment the index of the buffer */
            /* Check if the tag is of inline type */
            if (parse_attributes(buffer, &i, file_lexical, &lex, curr_node) == TAG_INLINE) {
                curr_node = curr_node->parent; /* Move to the parent node after reading */
                i++; /* Increment the buffer index */
                continue; /* Move to the next iterration */
            }

            /* Set the ending of the file_lexical string */
            file_lexical[lex] = '\0';
            if (!curr_node->tag) { /* If the tag of the node is null*/
                curr_node->tag = strdup(file_lexical); /* Set the node tag to the file_lexical value */
            }

            lex = 0; /* Reset the index of file_lexical */
            i++; /* Increment the index of the buffer */
            continue; /* Move to the next iterration */
        } else {
            if (!in_text) {
                lex = 0;  /* Reset the index of file_lexical if we are starting new text */
                in_text = 1; /* Change the value of the in_text */
            }
            file_lexical[lex++] = buffer[i++]; /* Add the character from the buffer to file_lexical */
        }
    }

    return TRUE; /* Exit function successfully*/
}

static void node_out(FILE* file, XMLNode* node, int indent, int times) {
    for (int i = 0; i < node->children.size; i++) {
        XMLNode* child = node->children.data[i];

        if (times > 0) /* Indent the node */
            fprintf(file, "%*s", indent * times, " ");
        
        /* Print the beginning tag */
        fprintf(file, "<%s", child->tag);
        for (int i = 0; i < child->attributes.size; i++) {
            XMLAttribute attr = child->attributes.data[i];
            if (!attr.value || !strcmp(attr.value, ""))
                continue;
            fprintf(file, " %s=\"%s\"", attr.key, attr.value); /* Print the attribute*/
        }

        if (child->children.size == 0 && !child->inner_text)
            fprintf(file, " />\n"); /* Print the closing of the tag */
        else {
            fprintf(file, ">");
            if (child->children.size == 0) /* Print the inner text and the closing tag */
                fprintf(file, "%s</%s>\n", child->inner_text, child->tag);
            else {
                fprintf(file, "\n"); /* Move to the next line */
                node_out(file, child, indent, times + 1);
                if (times > 0)
                    fprintf(file, "%*s", indent * times, ""); /* Indent the spacing +*/
                fprintf(file, "</%s>\n", child->tag); /* Print the tag name */
            }
        }
    }
}

static TagType parse_attributes(char* buffer, int* i, char* file_lexical, int* lex, XMLNode* curr_node) {
    XMLAttribute curr_attr = {0, 0}; /* Initialize the current attribute */
    
    while (buffer[*i] != '>') { /* Read untill the end of the tag */
        file_lexical[(*lex)++] = buffer[(*i)++]; /* Store each character from the tag name in the file_lexical string  */

        /* If a white space was found, but the tag name was not set yet, set the tag name */
        if (buffer[*i] == ' ' && !curr_node->tag) {
            file_lexical[*lex] = '\0'; /* Set the ending of the file_lexical string */
            curr_node->tag = strdup(file_lexical); /* Set the current node tag to file_lexical value */
            *lex = 0; /* Reset the index of file_lexical */
            (*i)++; /* Increment the buffer index */
            continue; /* Move to the next iterration */
        }

        /* Ignore white spaces for the case above */
        if (file_lexical[*lex-1] == ' ') {
            (*lex)--; /* Move the index of the file_lexical string back */
        }

        /* If an equal sign was found, there should be a key-value pair attribute */
        if (buffer[*i] == '=') {
            file_lexical[*lex] = '\0'; /* Set the ending of the file_lexical string */
            curr_attr.key = strdup(file_lexical); /* Set the attribute key to the file_lexical value */
            *lex = 0; /* Reset the file_lexical index */
            continue; /* Move to the next iterration */
        }

        /* Check for the quote character in order to get the attribute value */
        if (buffer[*i] == '"') {
            if (!curr_attr.key) { /* If the key of the attribute for the current node is null, print an error message and exit */
                fprintf(stderr, "Value has no key\n");
                return TAG_START; /* Mark the presence of a normal tag <example></example>*/
            }

            *lex = 0; /* Reset the index of the file_lexical string */
            (*i)++; /* Increment the index of the buffer */

            while (buffer[*i] != '"') /* Store all characters untill the second quote character is found */
                file_lexical[(*lex)++] = buffer[(*i)++];
            file_lexical[*lex] = '\0'; /* Set the ending of the file_lexical string */
            curr_attr.value = strdup(file_lexical); /* Set the attribute value for the key of the current node */
            XMLAttributeList_add(&curr_node->attributes, &curr_attr); /* Add the attribute to the attribute list */
            curr_attr.key = NULL; /* Nullify the key of the current attribute */
            curr_attr.value = NULL; /* Nullify the value of the current attribute */
            *lex = 0; /* Reset the index for the file_lexical */
            (*i)++; /* Increment the buffer index */
            continue; /* Move to the next iterration */
        }

        /* Check for an inline tag */
        if (buffer[*i - 1] == '/' && buffer[*i] == '>') {
            file_lexical[*lex] = '\0'; /* Set the ending of the file_lexical string */
            if (!curr_node->tag) /* If the tag of the current node is null*/
                curr_node->tag = strdup(file_lexical); /* Set the tag of the current node to the file_lexical value */
            (*i)++; /* Increment the buffer index */
            return TAG_INLINE; /* Mark the founding of an inline tag */
        }
    }

    return TAG_START; /* Mark the founding of a normal tag */
}

int XMLDocument_write(XMLDocument* doc, const char* path, int indent) {
    FILE* file = fopen(path, "w"); /* Open the new xml file in writting mode */
    if (!file) { /* If the file could not be oppened, print an error message and exit */
        fprintf(stderr, "Error! Could not open file '%s'\n", path);
        return FALSE;
    }

    /* Write the document version and encoding type */
    fprintf(
        file, "<?xml version=\"%s\" encoding=\"%s\" ?>\n",
        (doc->version) ? doc->version : "1.0",
        (doc->encoding) ? doc->encoding : "UTF-8"
    );

    node_out(file, doc->root, indent, 0);
    fclose(file); /* Close the file */
}

void XMLDocument_free(XMLDocument* document) {
    if (!document->root) { /* If the document root is already null, print an error message and exit */
        fprintf(stderr, "Error! Could not perform operations on a null document!\n");
        exit(EXIT_FAILURE);
    }

    XMLNode_free(document->root); /* Free the memory allocated to the document root */
    document->root = NULL; /* Nullify the document root */

    if (!document->encoding || !document->version) { /* If the version of encoding type is already null, print an error message and exit*/
        fprintf(stderr, "Error! Could not perform operations on a null document attribute!\n");
        exit(EXIT_FAILURE);
    }

    free(document->version); /* Free the memory allocated to the document version */
    free(document->encoding); /* Free the memory allocated to the document encoding type */
    document->encoding = NULL; /* Nullify the document encoding type */
    document->version = NULL; /* Nullify the document version */
}

void XMLAttribute_free(XMLAttribute* attr)
{
    if (!attr) { /* If the attribute is null print an error message and exit */
        fprintf(stderr, "Error! Cannot perform operations on a null attribute!\n");
        exit(EXIT_FAILURE);
    }
    free(attr->key); /* Free the key of the attribute */
    attr->key = NULL; /* Nullify the attribute key */
    free(attr->value);  /* Free the value of the attribute */
    attr->value = NULL; /* Nullify the attribute value */
}

void XMLAttributeList_init(XMLAttributeList* list) {
    list->heap_size = 1; /* Set the heap size for one attribute */
    list->size = 0; /* Set the number of attributes to zero */
    list->data = (XMLAttribute*) malloc(sizeof(XMLAttribute) * list->heap_size); /* Allocate memory for one attribute to the list */
}

void XMLAttributeList_add(XMLAttributeList* list, XMLAttribute* attr) {
    while (list->size >= list->heap_size) { /* as long as the number of items is larger than the size of the list, duble the list size */
        list->heap_size *= 2; 
        list->data = (XMLAttribute*) realloc(list->data, sizeof(XMLAttribute) * list->heap_size); /* Reallocate the memory for the attribute list with the new heap size */
    }

    list->data[list->size++] = *attr; /* Add the new attribute to the list */
}

void XMLNodeList_init(XMLNodeList* list) {
    list->heap_size = 1; /* Seet the heap size of the node list to one */
    list->size = 0; /* Set the number of attributes to zero */
    list->data = (XMLNode**) malloc(sizeof(XMLNode*) * list->heap_size); /* Allocate the memory for one element in the node list */
}

void XMLNodeList_add(XMLNodeList* list, XMLNode* node) {
    while (list->size >= list->heap_size) { /* as long as the number of items is larger than the size of the list, double the node list */
        list->heap_size *= 2; 
        list->data = (XMLNode**) realloc(list->data, sizeof(XMLNode*) * list->heap_size); /* Reallocate the memory for new number of elements */
    }

    list->data[list->size++] = node; /* Add the new element to the list */
}

XMLNode* XMLNodeList_at(XMLNodeList* list, int index) {
    return list->data[index]; /* Return the node at the position `index` */
}

void XMLNodeList_free(XMLNodeList* list)
{
    if (!list) { /* If the list is null, print an error message and exit */
        fprintf(stderr, "Error! Cannot perform operations on a null list!\n");
        exit(EXIT_FAILURE);
    }
    free(list); /* Free the memory allocated to the node list */
    list = NULL; /* Nullify the list */
}

XMLNode* XMLNode_new(XMLNode* parent) {
    /* Allocate memory for the current node */
    XMLNode* node = (XMLNode*) malloc(sizeof(XMLNode));
    node->parent = parent; /* Keep a pointer to the node parent */
    node->tag = NULL; /* Nullify the node tag */
    node->inner_text = NULL; /* Nullify the node inner text */
    XMLAttributeList_init(&node->attributes); /* Initialize the node attribute list */
    XMLNodeList_init(&node->children); /* Initialize the node children list */
    if (parent) /* If the node is not the root, add the node to it's parent children list */
        XMLNodeList_add(&parent->children, node);
    return node; /* Return the current node */
}

void XMLNode_free(XMLNode* node) {
    if (node->tag) /* If the node tag is not null, free the node */
        free(node->tag);
    if (node->inner_text) /* If the node inner text is not null, free the node */
        free(node->inner_text);
    for (int i = 0; i < node->attributes.size; i++) /* Free each attribute of the current node s*/
        XMLAttribute_free(&node->attributes.data[i]);
    free(node); /* Free the node */
    node = NULL; /* Nullify the node */
}

XMLNode* XMLNode_child(XMLNode* parent, int index) {
    return parent->children.data[index]; /* Return the node at a specific index */
}

XMLNodeList* XMLNode_children(XMLNode* parent, const char* tag) {
    /* Allocate the memory to the for the children list of the current node */
    XMLNodeList* list = (XMLNodeList*) malloc(sizeof(XMLNodeList));
    XMLNodeList_init(list); /* Initialize the list */

    for (int i = 0; i < parent->children.size; i++) {
        XMLNode* child = parent->children.data[i];
        if (!strcmp(child->tag, tag)) /* Add each child to the list */
            XMLNodeList_add(list, child);
    }

    return list; /* Return the list */
}

char* XMLNode_attr_val(XMLNode* node, char* key) {
    /* Search for the attribute in the node attribute list, that has a specific key*/
    for (int i = 0; i < node->attributes.size; i++) {
        XMLAttribute attr = node->attributes.data[i];
        if (!strcmp(attr.key, key)) /* If the node with the attribute key was found */
            return attr.value; /* Return the attribute value */
    }
    return NULL; /* If no node was found return null */
}

XMLAttribute* XMLNode_attr(XMLNode* node, char* key) {
    /* Search for an attribute in the node attribute list, that has a specific key*/
    for (int i = 0; i < node->attributes.size; i++) {
        XMLAttribute* attr = &node->attributes.data[i]; 
        if (!strcmp(attr->key, key)) /* If the node was found, return the attribute */
            return attr;
    }
    return NULL; /* If no node was found return null */
}

int ends_with(const char* haystack, const char* needle) {
    int h_len = strlen(haystack); /* Get the length of the string */
    int n_len = strlen(needle); /* Get the length of the substring */

    if (h_len < n_len) /* If the substring is longer than the string exit */
        return FALSE;

    for (int i = 0; i < n_len; i++) { /* Compare each letter of the substring with the letter of the string from a specific position */
        if (haystack[h_len - n_len + i] != needle[i]) /* If any letter does not match return false  */
            return FALSE;
    }

    return TRUE; /* If the string has the substring, return true */
}


#endif // LITTLE_XML_H