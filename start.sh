#!/bin/bash

echo "========================================"
echo "   Harukcal Spring Boot Application"
echo "========================================"
echo

echo "Checking Java version..."
if ! command -v java &> /dev/null; then
    echo "ERROR: Java is not installed or not in PATH"
    echo "Please install Java 17 or higher"
    exit 1
fi

java -version
echo

echo "Creating upload directory..."
sudo mkdir -p /upload
sudo chmod 755 /upload

echo
echo "Starting the application..."
echo "The application will be available at: http://localhost:8081"
echo "Press Ctrl+C to stop the application"
echo

./gradlew bootRun 