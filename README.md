# FastAPI Calculations Application

A full-stack web application for performing and managing mathematical calculations with user authentication and a history management system to store recent computations, built with FastAPI, SQLAlchemy, and modern web technologies.

## 🎯 Project Overview

This application provides a comprehensive calculation management system with the following features:

- **User Authentication**: Secure JWT-based authentication with access and refresh tokens
- **Calculation Management**: Create, read, update, and delete calculations (BREAD operations)
- **User Profile Management**: Update profile information and change passwords (NEW FEATURE)
- **Calculation Types**: Support for addition, subtraction, multiplication, and division


##  Calculator Features

This release includes a comprehensive user profile management system:

### Features Implemented:
- **Profile Information Updates**: Users can update their username, email, first name, and last name
- **Password Change**: Secure password change functionality with validation
- **Profile Viewing**: Display user account information including account status and timestamps
- **Real-time Validation**: Client-side validation with immediate feedback
- **Security**: 
  - Password strength requirements (8+ chars, uppercase, lowercase, numbers, special characters)
  - Current password verification before changes
  - Hashed password storage using bcrypt

### API Endpoints:
- `GET /api/profile` - Retrieve current user's profile
- `PUT /api/profile` - Update user profile information
- `POST /api/profile/change-password` - Change user password
- `GET /profile` - Profile management page (HTML)

### Testing Coverage:
- **Unit Tests**: Password hashing, validation logic, profile update logic
- **Integration Tests**: Database updates, API endpoints, authentication flows
- **E2E Tests**: Complete user workflows from login to profile updates using Playwright


## 📋 Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose
- PostgreSQL (if running locally without Docker)
- Redis (if running locally without Docker)
- Node.js and npm (for Playwright)

## 🚀 Quick Start

### Option 1: Using Docker (Recommended)

1. **Clone the repository**:
```bash
git clone <your-repo-url>
cd <repo-name>
```

2. **Create environment file**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Build and run with Docker Compose**:
```bash
docker-compose up --build
```

4. **Access the application**:
- Application: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- Alternative API Docs: http://localhost:8000/redoc

### Option 2: Local Development

1. **Clone and setup virtual environment**:
```bash
git clone git@github.com:TalashaW/FinalProject.git
cd FinalProject
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Run the application**:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 🧪 Running Tests

### Setup Testing Environment

1. **Install test dependencies**:
```bash
pip install -r requirements.txt
```

2. **Install Playwright browsers**:
```bash
playwright install
```

### Run All Tests

```bash
# Run all tests with coverage
pytest --cov=app --cov-report=html --cov-report=term

# View coverage report
open htmlcov/index.html  # On macOS
# OR
xdg-open htmlcov/index.html  # On Linux
# OR
start htmlcov/index.html  # On Windows
```

### Run Specific Test Types

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v

# E2E tests only
pytest tests/e2e/ -v

# Run with markers
pytest -m "unit" -v
pytest -m "integration" -v
pytest -m "e2e" -v
```

### Run Specific Test Files

```bash
# Test user profile functionality
pytest tests/unit/test_user_profile.py -v
pytest tests/integration/test_profile_api.py -v
pytest tests/e2e/test_profile_flow.py -v

# Test calculations
pytest tests/unit/test_calculations.py -v
pytest tests/integration/test_calculation_routes.py -v
pytest tests/e2e/test_calculation_flow.py -v
```

### Test with Different Verbosity

```bash
# Minimal output
pytest -q

# Verbose output
pytest -v

# Very verbose with print statements
pytest -vv -s
```

## 📦 Docker Hub Deployment

### Automated Deployment (GitHub Actions)

The application automatically builds and deploys to Docker Hub when:
1. All tests pass successfully
2. Code is pushed to the `main` branch
3. A new tag is created

**Docker Hub Repository**: `<your-dockerhub-username>/fastapi-calculations-app`

### Pull and Run from Docker Hub

```bash
# Pull the latest image
docker pull twin632
/fastapi-calculations-app:latest

# Run the container
docker compose up -d
```

### Manual Docker Build

```bash
# Build the image
docker build -t fastapi-calculations-app:latest .

# Tag for Docker Hub
docker tag fastapi-calculations-app:latest <your-dockerhub-username>/fastapi-calculations-app:latest

# Push to Docker Hub
docker push <your-dockerhub-username>/fastapi-calculations-app:latest
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Database Configuration
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/fastapi_db

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_REFRESH_SECRET_KEY=your-refresh-secret-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
BCRYPT_ROUNDS=12

# CORS (if needed)
CORS_ORIGINS=[" http://localhost:8000"]
```



## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Login with username/password (JSON) |
| POST | `/auth/token` | Login with form data (Swagger UI) |

### User Profile Endpoints (NEW)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profile` | Get current user's profile |
| PUT | `/api/profile` | Update user profile information |
| POST | `/api/profile/change-password` | Change user password |
| GET | `/profile` | Profile management page |

### Calculation Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/calculations` | Create a new calculation |
| GET | `/calculations` | List all user's calculations |
| GET | `/calculations/{calc_id}` | Get specific calculation |
| PUT | `/calculations/{calc_id}` | Update calculation inputs |
| DELETE | `/calculations/{calc_id}` | Delete a calculation |

### Web Pages

| Endpoint | Description |
|----------|-------------|
| `/` | Landing page |
| `/login` | Login page |
| `/register` | Registration page |
| `/dashboard` | User dashboard with calculations |
| `/dashboard/view/{calc_id}` | View calculation details |
| `/dashboard/edit/{calc_id}` | Edit calculation |
| `/profile` | User profile management (NEW) |

### Interactive API Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    password VARCHAR NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE
);
```

### Calculations Table
```sql
CREATE TABLE calculations (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    inputs JSON NOT NULL,
    result FLOAT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

## 🔐 Security Features

- **Password Hashing**: Bcrypt with configurable rounds
- **JWT Authentication**: Access and refresh token system
- **Token Blacklisting**: Redis-based token revocation
- **Input Validation**: Pydantic schemas for all inputs
- **SQL Injection Protection**: SQLAlchemy ORM
- **CORS Configuration**: Configurable cross-origin settings
- **Password Requirements**: 
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character

## 📁 Project Structure

```
.
├── app/
│   ├── auth/
│   │   ├── dependencies.py      # Auth dependencies
│   │   ├── jwt.py               # JWT token management
│   │   └── redis.py             # Redis token blacklist
│   ├── core/
│   │   └── config.py            # Configuration settings
│   ├── models/
│   │   ├── user.py              # User model
│   │   └── calculation.py       # Calculation models
│   ├── schemas/
│   │   ├── user.py              # User schemas
│   │   ├── calculation.py       # Calculation schemas
│   │   ├── token.py             # Token schemas
│   │   └── base.py              # Base schemas
│   ├── database.py              # Database connection
│   ├── database_init.py         # Database initialization
│   └── main.py                  # FastAPI application
├── templates/
│   ├── layout.html              # Base template
│   ├── index.html               # Landing page
│   ├── login.html               # Login page
│   ├── register.html            # Registration page
│   ├── dashboard.html           # Dashboard
│   ├── user_profile.html        # Profile management (NEW)
│   ├── view_calculation.html    # View calculation
│   └── edit_calculation.html    # Edit calculation
├── static/
│   ├── css/
│   │   └── style.css            # Custom styles
│   └── img/
│       └── favicon.ico          # Favicon
├── tests/
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── e2e/                     # End-to-end tests
├── .github/
│   └── workflows/
│       └── ci-cd.yml            # GitHub Actions CI/CD
├── Dockerfile                   # Docker configuration
├── docker-compose.yml           # Docker Compose setup
├── requirements.txt             # Python dependencies
├── requirements-test.txt        # Test dependencies
├── pytest.ini                   # Pytest configuration
├── .env.example                 # Environment template
└── README.md                    # This file
```

## 🧑‍💻 Development Workflow

### Adding New Features

1. **Create a new branch**:
```bash
git checkout -b feature/your-feature-name
```

2. **Make changes**:
   - Update models if needed
   - Create/update schemas
   - Implement routes
   - Add frontend components
   - Write tests

3. **Run tests locally**:
```bash
pytest --cov=app
```

4. **Commit and push**:
```bash
git add .
git commit -m "Add: your feature description"
git push origin feature/your-feature-name
```

5. **Create Pull Request** on GitHub

6. **CI/CD Pipeline** will automatically:
   - Run all tests
   - Check code coverage
   - Build Docker image
   - Push to Docker Hub (on merge to main)

### Code Quality

```

```

## 🐛 Troubleshooting

### Common Issues

**Issue**: Cannot connect to database
```bash
# Solution: Check if PostgreSQL is running
docker ps | grep postgres

# Restart database
docker-compose restart db
```

**Issue**: Redis connection failed
```bash
# Solution: Check if Redis is running
docker ps | grep redis

# Restart Redis
docker-compose restart redis
```

**Issue**: Tests failing due to database
```bash
# Solution: Reset test database
docker-compose down -v
docker-compose up -d
```

**Issue**: Port already in use
```bash
# Solution: Find and kill process using port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port
uvicorn app.main:app --port 8001
```

## 📊 Testing Strategy

### Unit Tests
- Test individual functions and methods
- Mock external dependencies
- Focus on business logic
- Coverage target: >80%

### Integration Tests
- Test API endpoints
- Test database interactions
- Test authentication flows
- Use test database

### E2E Tests
- Test complete user workflows
- Test UI interactions
- Test cross-browser compatibility
- Use Playwright for automation
