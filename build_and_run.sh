#!/bin/bash

# Ensure ports are not in use
fuser -k 12345/tcp
fuser -k 8888/tcp

# Compile server
gcc -o server server.c db.c rest_client.c conversion.h -lmicrohttpd -lsqlite3 -lpthread -lcurl -lcjson
if [ $? -ne 0 ]; then
    echo "Error compiling server"
    exit 1
fi

# Run server
./server &
SERVER_PID=$!
echo "Server is running with PID $SERVER_PID"

# Compile simple_client
gcc -o simple_client simple_client.c -lpthread
if [ $? -ne 0 ]; then
    echo "Error compiling simple_client"
    kill $SERVER_PID
    exit 1
fi

# Compile admin_client
gcc -o admin_client admin_client.c -lpthread
if [ $? -ne 0 ]; then
    echo "Error compiling admin_client"
    kill $SERVER_PID
    exit 1
fi

# Wait for user to end the server
read -p "Press Enter to stop the server..."

# Stop server
kill $SERVER_PID
echo "Server stopped."
