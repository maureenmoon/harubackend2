# Running in Spring Tool Suite (STS)

## 🚀 Quick Start for STS

### Prerequisites

- **Spring Tool Suite 4.x** or **Eclipse with Spring Tools**
- **Java 17** or higher
- **MySQL 8.0** or higher
- **Git** (to clone the repository)

## 📋 Setup Steps

### Step 1: Import Project into STS

1. **Open STS**
2. **File → Import**
3. **Gradle → Existing Gradle Project**
4. **Browse** to your project directory: `C:\msmoon\07dev\haruSpring-main\haruSpring-main`
5. **Click Next** and **Finish**

### Step 2: Configure Database

1. **Open** `src/main/resources/application.properties`
2. **Update** database credentials:

```properties
spring.datasource.username=your_username
spring.datasource.password=your_password
```

### Step 3: Create Upload Directory

**Windows:**

```cmd
mkdir C:\upload
```

**Linux/Mac:**

```bash
sudo mkdir -p /upload
sudo chmod 755 /upload
```

### Step 4: Run the Application

#### Method 1: Right-click Run

1. **Right-click** on `HarukcalApplication.java`
2. **Run As → Spring Boot App**

#### Method 2: Run Configuration

1. **Run → Run Configurations**
2. **Spring Boot App → New Configuration**
3. **Project**: Select your project
4. **Main Type**: `com.study.spring.HarukcalApplication`
5. **Click Apply and Run**

#### Method 3: Gradle Run

1. **Window → Show View → Gradle Tasks**
2. **Expand** your project
3. **Double-click** `bootRun`

## 🔧 STS Configuration

### Java Version

1. **Project Properties → Java Compiler**
2. **Compiler compliance level**: 17
3. **Apply and Close**

### Gradle Configuration

1. **Project Properties → Gradle**
2. **Gradle wrapper**: Use project default
3. **Apply and Close**

### Build Path

1. **Project Properties → Java Build Path**
2. **Libraries**: Ensure all dependencies are resolved
3. **Apply and Close**

## 🐛 Troubleshooting in STS

### Build Errors

1. **Project → Clean**
2. **Gradle → Refresh Gradle Project**
3. **Check** Error Log view for details

### Port Already in Use

1. **Open** `application.properties`
2. **Change** port:

```properties
server.port=8082
```

### Database Connection Issues

1. **Ensure** MySQL is running
2. **Verify** database `harukcal2` exists
3. **Check** credentials in `application.properties`

### Gradle Issues

1. **Gradle → Refresh Gradle Project**
2. **Project → Clean**
3. **Check** Gradle Console for errors

## 📊 Monitoring in STS

### Console Output

- **Console** view shows application logs
- **Spring Boot Dashboard** shows running applications

### Debug Mode

1. **Right-click** `HarukcalApplication.java`
2. **Debug As → Spring Boot App**
3. **Set breakpoints** in your code

### Logs

- **Error Log** view for compilation errors
- **Console** view for runtime logs
- **Spring Boot Dashboard** for application status

## 🎯 Verification

### Health Check

1. **Open** browser: `http://localhost:8081/api/health`
2. **Should see**: `{"status":"UP","message":"Application is running"}`

### Database Connection

- **Check** console for: `HikariPool-1 - Start completed`
- **Check** console for: `Initialized JPA EntityManagerFactory`

### Security Configuration

- **Check** console for: `Will secure any request with filters`
- **Check** console for: `55 mappings in 'requestMappingHandlerMapping'`

## 🔍 Useful STS Views

### Spring Boot Dashboard

- **Window → Show View → Spring Boot Dashboard**
- Shows running Spring Boot applications
- Quick access to restart/stop applications

### Gradle Tasks

- **Window → Show View → Gradle Tasks**
- Run Gradle tasks directly from STS
- Useful for `clean`, `build`, `bootRun`

### Console

- **Window → Show View → Console**
- Shows application output and logs
- Multiple console tabs for different outputs

### Error Log

- **Window → Show View → Error Log**
- Shows compilation and runtime errors
- Helpful for debugging issues

## 🚀 Advanced STS Features

### Hot Reload

1. **Install** Spring Boot DevTools dependency
2. **Save** any file to trigger hot reload
3. **Changes** are automatically applied

### Debugging

1. **Set breakpoints** in your code
2. **Debug As → Spring Boot App**
3. **Step through** code execution

### Code Completion

- **Spring Boot** specific completions
- **JPA** repository method suggestions
- **Thymeleaf** template completions

## 📝 Common STS Commands

### Project Management

- **F5**: Refresh project
- **Ctrl+Shift+O**: Organize imports
- **Ctrl+Shift+F**: Format code

### Running

- **Ctrl+F11**: Run last application
- **F11**: Debug last application
- **Ctrl+Shift+F11**: Run as Spring Boot App

### Navigation

- **Ctrl+Shift+R**: Open resource
- **Ctrl+Shift+T**: Open type
- **Ctrl+1**: Quick fix

## 🎉 Success Indicators

✅ **Application starts** without errors  
✅ **Console shows**: "Started HarukcalApplication"  
✅ **Health endpoint** responds: `http://localhost:8081/api/health`  
✅ **Database connected**: "HikariPool-1 - Start completed"  
✅ **Security configured**: "55 mappings in 'requestMappingHandlerMapping'"  
✅ **CORS enabled**: Global CORS configuration active

## 🆘 Need Help?

1. **Check** Error Log view for specific errors
2. **Review** Console output for runtime issues
3. **Verify** all prerequisites are met
4. **Try** running with `--debug` flag for verbose output
5. **Check** the main [README.md](README.md) for detailed documentation
