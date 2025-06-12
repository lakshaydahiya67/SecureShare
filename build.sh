#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "🔨 Starting build process..."

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Collect static files
echo "📁 Collecting static files..."
python manage.py collectstatic --no-input

# Run database migrations
echo "🗄️ Running database migrations..."
python manage.py migrate

# Create superuser if none exists
echo "👤 Creating superuser if needed..."
python manage.py create_superuser_if_none_exists

echo "✅ Build completed successfully!"