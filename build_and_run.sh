#!/bin/bash

# Asigură-te că porturile nu sunt utilizate
fuser -k 12345/tcp
fuser -k 8888/tcp

# Compilare server
gcc -o server server.c db.c rest_client.c -lmicrohttpd -lsqlite3 -lpthread -lcurl -lcjson
if [ $? -ne 0 ]; then
    echo "Eroare la compilarea serverului"
    exit 1
fi

# Rulare server
./server
echo "Serverul este pornit și rulează."

# Compilare simple_client
gcc -o simple_client simple_client.c -lpthread
if [ $? -ne 0 ]; then
    echo "Eroare la compilarea simple_client"
    exit 1
fi

# Compilare admin_client
gcc -o admin_client admin_client.c -lpthread
if [ $? -ne 0 ]; then
    echo "Eroare la compilarea admin_client"
    exit 1
fi