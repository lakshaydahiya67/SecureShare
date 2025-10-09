# SecureShare
SecureShare is a secure file sharing platform built with Django that enables secure file management with role-based access control and encrypted file transfers. The application provides separate interfaces for operations users who can upload files and client users who can download them through secure, single-use links.

## Features

### Core Features
- **Role-Based Access Control**: Two distinct user types with different permissions
  - **Operations Users**: Can upload, manage, and view all files
  - **Client Users**: Can view and download files through secure links
- **Email Verification**: Client users must verify their email before accessing files
- **Secure File Storage**: Files are stored with unique identifiers and accessed through encrypted tokens
- **Single-Use Download Links**: Each download link is valid for 24 hours and expires after use
- **File Type Validation**: Only supports secure document formats (.docx, .pptx, .xlsx)
- **AI-Powered File Summarization**: Generate intelligent summaries of document contents using Google Gemini AI

### Security Features
- **Session-Based Authentication**: RESTful API with Django session authentication and CSRF protection
- **Encrypted File Access**: Download links use encrypted tokens for secure file access
- **Session Management**: Web interface with proper session handling
- **File Upload Validation**: Strict file type and size validation

### User Interface
- **Responsive Web Interface**: Modern, mobile-friendly design
- **Separate User Dashboards**: Different interfaces based on user type
- **Real-Time File Management**: Dynamic file listing and upload progress
- **Email Templates**: Professional email verification templates

## Technology Stack

- **Backend**: Django 5.2 + Django REST Framework
- **Database**: SQLite (development) / PostgreSQL (production ready)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Authentication**: Django Session Authentication with CSRF protection
- **File Security**: Cryptography library with Fernet encryption
- **Email**: Django Email Framework (console backend for development)
- **AI Integration**: Google Gemini for document analysis and summarization

## Project Structure

```
SecureShare/
├── core/           # Core utilities (permissions, encryption, validators)
├── users/          # User management (authentication, email verification)
├── files/          # File management (upload, download, access control)
├── templates/      # HTML templates for web interface
├── static/         # CSS, JavaScript, and static assets
├── media/          # File upload storage
└── SecureShare/    # Django project settings
```

## API Endpoints

### Authentication
- `POST /api/users/signup/` - User registration
- `POST /api/users/login/` - User login
- `GET /api/users/verify/{token}/` - Email verification

### File Management
- `POST /api/files/upload/` - File upload (Operations only)
- `GET /api/files/list/` - List available files
- `GET /api/files/download-link/{file_id}/` - Get secure download link
- `GET /api/files/download/{token}/` - Download file with token
- `GET /api/files/summarize/{file_id}/` - Generate AI summary of file content

### Web Interface
- `/` - Landing page
- `/login/` - Login page
- `/signup/` - Registration page
- `/upload/` - File upload (Operations users)
- `/files/` - File listing (All users)

## Setup Instructions

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)
- Google Gemini API key (for AI features)
- Email account with app password (optional, for production email features)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/lakshaydahiya67/SecureShare
   cd SecureShare
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

1. Navigate to the Django project directory:
   ```bash
   cd SecureShare
   ```

2. **Create environment configuration**:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   ```

3. **Get your API keys**:
   
   **Google Gemini API Key** (Required for AI features):
   - Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Sign in with your Google account
   - Click "Create API Key"
   - Copy the generated key
   
   **Django Secret Key** (Required):
   - Generate a secure key using: `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`
   - Or use an online generator like [djecrety.ir](https://djecrety.ir/)

4. **Configure your .env file** with your actual values:
   ```bash
   # Open .env in your text editor and update:
   
   # Required: Paste your actual Gemini API key
   GEMINI_API_KEY=AIzaSyC...your-actual-key-here
   
   # Required: Paste your generated Django secret key  
   SECRET_KEY=django-insecure-your-actual-key-here
   
   # Development settings
   DEBUG=True
   
   # Optional: Configure email (defaults to console for development)
   EMAIL_HOST_USER=your-email@gmail.com
   EMAIL_HOST_PASSWORD=your-app-password
   
   # Optional: Database (defaults to SQLite)
   # DATABASE_URL=postgresql://user:password@host:port/dbname
   ```

5. **Set up the database**:
   ```bash
   python manage.py migrate
   ```

6. **Create a superuser** (optional, for admin access):
   ```bash
   python manage.py createsuperuser
   # OR use the automated command:
   python manage.py create_superuser_if_none_exists
   ```

### Running the Server

1. Start the development server:
   ```bash
   python manage.py runserver
   ```

2. Access the application:
   - Web Interface: `http://localhost:8000`
   - API Base URL: `http://localhost:8000/api/`
   - Admin Interface: `http://localhost:8000/admin/`

## Usage Guide

### For Operations Users

1. **Register** as an Operations user at `/signup/`
2. **Login** to access the upload interface
3. **Upload Files**: Navigate to `/upload/` to upload .docx, .pptx, or .xlsx files
4. **Manage Files**: View all uploaded files and their download statistics
5. **AI Summaries**: Use the "Summarize" button to get intelligent AI-generated summaries of file contents

### For Client Users

1. **Register** as a Client user at `/signup/`
2. **Verify Email**: Check your email and click the verification link
3. **Login** to access the file listing
4. **Download Files**: View available files and get secure download links
5. **AI Summaries**: Use the "Summarize" button to get quick overviews of file contents before downloading
6. **Access Files**: Use the provided links to download files (links expire after 24 hours)

### API Usage

Use the RESTful API for programmatic access:

1. **Authenticate**: POST to `/api/users/login/` to establish a session
2. **Include Cookies**: Ensure session cookies are included in subsequent requests
3. **CSRF Protection**: Include `X-CSRFToken` header for unsafe HTTP methods
4. **Upload Files**: POST multipart/form-data to `/api/files/upload/` (with CSRF token)
5. **List Files**: GET `/api/files/list/` to see available files
6. **Download**: GET `/api/files/download-link/{id}/` (authenticated) then use the download token

## File Security

### Upload Security
- File type validation (only .docx, .pptx, .xlsx allowed)
- Unique file naming to prevent conflicts
- Secure file storage with random UUIDs

### Download Security
- Single-use encrypted download tokens
- Time-based expiration (24 hours)
- Access logging and tracking
- Role-based access control
- Session-based authentication with CSRF protection

## Development

### Running Tests

To run tests with coverage:
```bash
pytest  # This will generate coverage reports in htmlcov/ and coverage.xml
```

To view the coverage report in your browser:
```bash
open htmlcov/index.html  # On macOS
# or
xdg-open htmlcov/index.html  # On Linux
```

### Project Dependencies

Key packages used in this project:
- **Django 5.2**: Web framework
- **Django REST Framework**: API development
- **cryptography**: File encryption and token security
- **Google Generative AI**: AI-powered document analysis and summarization
- **python-docx**: Word document processing
- **python-pptx**: PowerPoint document processing  
- **openpyxl**: Excel document processing
- **python-dotenv**: Environment variable management

### Database Models

- **User**: Custom user model with role-based fields
- **File**: File metadata and storage information  
- **FileAccess**: Download token management and tracking
- **Sessions**: User authentication state management (Django built-in)

### Testing

For API testing, refer to the Postman collection in `/postman/check_api.txt` which includes:
- Complete API endpoint documentation
- Sample requests and responses
- Authentication workflows
- File upload/download examples

## Production Deployment

### Environment Variables
Set these environment variables for production:
```bash
SECRET_KEY=your-secret-key
DEBUG=False
DATABASE_URL=your-database-url
EMAIL_HOST=your-smtp-host
EMAIL_HOST_USER=your-email
EMAIL_HOST_PASSWORD=your-email-password
ENCRYPTION_KEY=your-32-byte-encryption-key
GEMINI_API_KEY=your-gemini-api-key
```

### Security Checklist
- [ ] Set `DEBUG = False`
- [ ] Configure secure `SECRET_KEY`
- [ ] Set up proper database (PostgreSQL)
- [ ] Configure SMTP email backend
- [ ] Set up HTTPS/SSL
- [ ] Configure proper file storage (AWS S3, etc.)
- [ ] Set up monitoring and logging

### Deployment Options
- **Traditional**: Apache/Nginx + Gunicorn
- **Container**: Docker deployment
- **Cloud**: Heroku, AWS, DigitalOcean
- **Serverless**: AWS Lambda with Zappa

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation in `/postman/check_api.txt`
- Review the code comments for implementation details