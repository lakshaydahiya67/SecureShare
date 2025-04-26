# SecureShare

SecureShare is a secure file sharing platform built with Django that enables secure file management with role-based access control and encrypted file transfers.

## Features

- **User Authentication**: Custom user model with token-based authentication
- **Email Verification**: Email verification system for account security
- **Secure File Storage**: Encrypted file storage and transfer
- **API Access**: RESTful API using Django REST Framework
- **Role-Based Access Control**: Different permission sets for different user types

## Technology Stack

- **Backend**: Django 5.2 + Django REST Framework
- **Database**: SQLite (default) - configurable for other databases
- **Authentication**: Token-based authentication
- **File Encryption**: Base64 encryption for secure file handling

## Setup Instructions

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)

### Installation

1. Clone the repository
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

1. Set up the database:
   ```bash
   python manage.py migrate
   ```
2. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```
3. Configure email settings in `settings.py` for your environment
4. For production, configure a more secure `SECRET_KEY` and set `DEBUG = False`

### Running the Server