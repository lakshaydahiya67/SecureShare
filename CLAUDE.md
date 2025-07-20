act as a senior developer and use DRY principle.
do not over-engineer, our goal is to only make MVP.
make sure there are no linting errors.
For maximum efficiency, whenever you need to perform multiple independent operations, invoke all relevant tools simultaneously rather than sequentially.
Call the web search tool when: user asks about current events, factual information after January 2025, or any query requiring real-time data. Be proactive in identifying when searches would enhance your response.

## The Ten Universal Commandments

1. **Thou shalt ALWAYS use MCP tools before coding**  
2. **Thou shalt NEVER assume; always question**  
3. **Thou shalt write code that's clear and obvious**  
4. **Thou shalt be BRUTALLY HONEST in assessments**  
5. **Thou shalt PRESERVE CONTEXT, not delete it**  
6. **Thou shalt make atomic, descriptive commits**  
7. **Thou shalt document the WHY, not just the WHAT**  
8. **Thou shalt test before declaring done**  
9. **Thou shalt handle errors explicitly**  
10. **Thou shalt treat user data as sacred**  

---

## Final Reminders

- Codebase > Documentation > Training data (in order of truth)  
- Research current docs, don’t trust outdated knowledge  
- Ask questions early and often  
- Use slash commands for consistent workflows  
- Derive documentation on-demand  
- Extended thinking for complex problems  
- Visual inputs for UI/UX debugging  
- Test locally before pushing  
- Think simple: clear, obvious, no bullshit  

---

> **Remember:** Write code as if the person maintaining it is a violent psychopath who knows where you live. Make it that clear.


# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Setup and Dependencies
```bash
# Install dependencies
pip install -r requirements.txt

# Database setup
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser

# Production build process
./build.sh
```

### Running the Application
```bash
# Development server
python manage.py runserver

# Access points:
# - Web Interface: http://localhost:8000
# - API Base: http://localhost:8000/api/
# - Admin: http://localhost:8000/admin/
```

### Django Management Commands
```bash
# Run migrations
python manage.py migrate

# Create migrations
python manage.py makemigrations

# Collect static files
python manage.py collectstatic

# Create superuser if none exists (custom command)
python manage.py create_superuser_if_none_exists

# Run tests with Django test runner
python manage.py test

# Run tests with pytest (recommended)
pytest

# Run tests with coverage
pytest --cov=. --cov-report=html --cov-report=term-missing

# Run specific test modules
pytest core/tests.py
pytest users/tests.py
pytest files/tests.py
pytest tests/test_integration.py

# Run tests with specific markers
pytest -m unit
pytest -m integration
pytest -m api
```

## Architecture Overview

### Project Structure
- **SecureShare/**: Django project configuration and settings
- **core/**: Shared utilities (encryption, permissions, validators, AI services)
- **users/**: User management with role-based authentication and email verification
- **files/**: File upload, download, and access control with secure token-based links
- **templates/**: HTML templates for web interface
- **static/**: CSS, JavaScript, and static assets

### Key Components

**Authentication System**: 
- Custom User model with two roles: Operations Users (upload/manage files) and Client Users (download files)
- Email verification required for Client Users
- Token-based API authentication via Django REST Framework

**File Security Architecture**:
- Files stored with UUID-based names in `media/uploads/`
- Secure download system using encrypted tokens with 24-hour expiration
- Single-use download links managed through FileAccess model
- File type validation (only .docx, .pptx, .xlsx allowed)

**Encryption System** (`core/encryption.py`):
- Fernet symmetric encryption for download tokens
- Environment-based encryption key management
- URL-safe base64 encoding for token transmission

**AI Integration** (`core/ai_service.py`):
- Google Gemini API integration for document summarization
- Supports processing of .docx, .pptx, and .xlsx files

### Models
- **User**: Custom user model with email authentication and role-based access
- **File**: File metadata with uploader tracking
- **FileAccess**: Manages secure download tokens and access tracking

### Environment Variables
Required for production:
- `SECRET_KEY`: Django secret key
- `DEBUG`: Boolean for debug mode
- `DATABASE_URL`: PostgreSQL connection string (optional, defaults to SQLite)
- `GEMINI_API_KEY`: Google Gemini API key for AI features
- Email configuration: `EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`

### API Endpoints
Authentication: `/api/users/signup/`, `/api/users/login/`, `/api/users/verify/{token}/`
Files: `/api/files/upload/`, `/api/files/list/`, `/api/files/download-link/{id}/`, `/api/files/download/{token}/`, `/api/files/summarize/{id}/`

### Security Features
- CSRF protection with trusted origins for production deployment
- HTTPS enforcement in production
- Role-based permissions (Operations vs Client users)
- Encrypted file access tokens
- Email verification for client users
- File type validation and secure storage