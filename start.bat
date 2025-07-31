@echo off
echo ========================================
echo    Harukcal Spring Boot Application
echo ========================================
echo.

echo Checking Java version...
java -version
if %errorlevel% neq 0 (
    echo ERROR: Java is not installed or not in PATH
    echo Please install Java 17 or higher
    pause
    exit /b 1
)

echo.
echo Creating upload directory...
if not exist "C:\upload" mkdir "C:\upload"

echo.
echo Starting the application...
echo The application will be available at: http://localhost:8081
echo Press Ctrl+C to stop the application
echo.

gradlew.bat bootRun

pause 