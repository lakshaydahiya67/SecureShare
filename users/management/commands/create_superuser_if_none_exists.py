from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import os

class Command(BaseCommand):
    help = 'Create a superuser if none exists'

    def handle(self, *args, **options):
        User = get_user_model()
        
        if not User.objects.filter(is_superuser=True).exists():
            # Get environment variables
            username = os.environ.get('SUPERUSER_USERNAME', 'admin')
            email = os.environ.get('SUPERUSER_EMAIL', 'admin@example.com')
            password = os.environ.get('SUPERUSER_PASSWORD', 'password')
            
            try:
                # Create superuser with your custom User model
                # Your create_superuser method signature: create_superuser(email, password=None, **extra_fields)
                user = User.objects.create_superuser(
                    email=email,
                    password=password,
                    first_name=username.split()[0] if ' ' in username else username,  # Extract first name
                    last_name=' '.join(username.split()[1:]) if ' ' in username else '',  # Extract last name
                    user_type=User.UserType.OPERATION,  # Superuser should be operation user
                    is_email_verified=True,  # Superuser should have verified email
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Superuser created successfully!')
                )
                self.stdout.write(
                    self.style.SUCCESS(f'   Email: {user.email}')
                )
                self.stdout.write(
                    self.style.SUCCESS(f'   Name: {user.first_name} {user.last_name}')
                )
                self.stdout.write(
                    self.style.SUCCESS(f'   User Type: {user.get_user_type_display()}')
                )
                self.stdout.write(
                    self.style.SUCCESS(f'   Email Verified: {user.is_email_verified}')
                )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'❌ Failed to create superuser: {e}')
                )
                
        else:
            # Show existing superuser info
            existing_superuser = User.objects.filter(is_superuser=True).first()
            self.stdout.write(
                self.style.WARNING(f'⚠️  Superuser already exists!')
            )
            self.stdout.write(
                self.style.WARNING(f'   Email: {existing_superuser.email}')
            )
            self.stdout.write(
                self.style.WARNING(f'   Name: {existing_superuser.first_name} {existing_superuser.last_name}')
            )
            self.stdout.write(
                self.style.WARNING(f'   User Type: {existing_superuser.get_user_type_display()}')
            )