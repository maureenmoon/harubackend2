# Quick Setup Guide

## 🚀 Quick Start (5 minutes)

### Prerequisites Check

- ✅ Java 17+ installed
- ✅ MySQL 8.0+ running
- ✅ Git (to clone the repository)

### Step 1: Database Setup

1. Create MySQL database:

```sql
CREATE DATABASE harukcal2;
```

2. Update database credentials in `src/main/resources/application.properties`:

```properties
spring.datasource.username=your_username
spring.datasource.password=your_password
```

### Step 2: Run the Application

#### Windows Users:

```bash
# Double-click start.bat or run:
start.bat
```

#### Linux/Mac Users:

```bash
# Make script executable and run:
chmod +x start.sh
./start.sh
```

#### Manual Start:

```bash
# Clean and run
./gradlew clean bootRun
```

### Step 3: Verify Installation

1. Open browser: http://localhost:8081/api/health
2. Should see: `{"status":"UP","message":"Application is running"}`

## 🔧 Configuration Options

### Change Port (if 8081 is busy)

Edit `src/main/resources/application.properties`:

```properties
server.port=8082
```

### Disable SQL Logging

Edit `src/main/resources/application.properties`:

```properties
spring.jpa.show-sql=false
logging.level.org.hibernate.SQL=error
```

### Change Upload Directory

Edit `src/main/resources/application.properties`:

```properties
file.upload-dir=D:/my-uploads/
```

## 🐛 Common Issues

### "Port already in use"

- Change port in `application.properties`
- Or kill existing process: `netstat -ano | findstr :8081`

### "Database connection failed"

- Check MySQL is running
- Verify database exists: `harukcal2`
- Check credentials in `application.properties`

### "Upload directory not found"

- Windows: Create `C:\upload` folder
- Linux/Mac: Create `/upload` folder with proper permissions

### "Java not found"

- Install Java 17 or higher
- Add Java to PATH environment variable

## 📞 Need Help?

1. Check the full [README.md](README.md) for detailed documentation
2. Review application logs for error messages
3. Ensure all prerequisites are met
4. Try running with `./gradlew bootRun --debug` for verbose output

## 🎯 What's Working

✅ **Authentication**: JWT login/logout with refresh tokens  
✅ **User Management**: Create, update, delete users  
✅ **Image Upload**: Profile images with compression and thumbnails  
✅ **Calorie Calculation**: Mifflin-St Jeor equation  
✅ **CORS**: Frontend integration ready  
✅ **Database**: MySQL with automatic schema updates  
✅ **Security**: Spring Security with JWT authentication

## 🔗 API Endpoints

- **Health**: `GET http://localhost:8081/api/health`
- **Login**: `POST http://localhost:8081/api/members/login`
- **Profile**: `GET http://localhost:8081/api/members/me`
- **Upload Image**: `POST http://localhost:8081/api/members/me/upload-profile-image`
- **Calories**: `GET http://localhost:8081/api/members/me/recommended-calories-calculation`
