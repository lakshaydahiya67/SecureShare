# SecureShare

SecureShare is a secure file sharing platform that allows operations users to upload files and client users to download them through secure, single-use links.

## Features

- **User Authentication**: Separate login flows for operations and client users
- **Email Verification**: Client users must verify their email before accessing the system
- **File Upload**: Operations users can upload .docx, .pptx, and .xlsx files
- **Secure Downloads**: Files are accessed through encrypted, single-use download links
- **Role-Based Access Control**: Different permissions for operations and client users
- **Responsive UI**: Works on desktop and mobile devices

## Technology Stack

- **Backend**: Django + Django REST Framework
- **Database**: SQLite (development) / PostgreSQL (production)
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Token-based authentication, email verification, encrypted file access links

## Setup Instructions

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)

### Installation

1. Clone the repository