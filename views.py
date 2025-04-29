from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.conf import settings
from authlib.integrations.django_client import OAuth
from pymysql.cursors import DictCursor
import json
import re
from datetime import datetime, timedelta
import traceback
# OAuth Login (Initiates OAuth flow)
from django.conf import settings
from django.http import JsonResponse
from authlib.integrations.django_client import OAuth
from datetime import datetime, timedelta
import traceback
import os
from auth_app.db_config import (
    get_db_connection,
    hash_password,
    verify_password,
    validate_password
)

# Rate limiting configuration
RATE_LIMIT = {
    'signup': {'requests': 20, 'period': 7200},  # 5 requests per hour
    'signin': {'requests': 20, 'period': 600}    # 5 requests per 5 minutes
}

# Helper function to get client IP
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Helper function to check rate limits
def check_rate_limit(request, endpoint):
    ip = get_client_ip(request)
    cache_key = f"{endpoint}_{ip}"
    requests = cache.get(cache_key, 0)

    if requests >= RATE_LIMIT[endpoint]['requests']:
        return False

    cache.set(cache_key, requests + 1, RATE_LIMIT[endpoint]['period'])
    return True

# Email format validation
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

# First name and last name format validation
def validate_name(name):
    pattern = r'^[a-zA-Z]{2,30}$'
    return bool(re.match(pattern, name))

# Signup API
@csrf_exempt
def signup_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    if not check_rate_limit(request, 'signup'):
        return JsonResponse({'error': 'Too many signup attempts. Please try again later.'}, status=429)

    try:
        data = json.loads(request.body)
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not all([first_name, last_name, email, password]):
            return JsonResponse({'error': 'All fields are required'}, status=400)

        if not validate_email(email):
            return JsonResponse({'error': 'Invalid email format'}, status=400)

        if not (validate_name(first_name) and validate_name(last_name)):
            return JsonResponse({'error': 'Invalid first name or last name format'}, status=400)

        is_valid, message = validate_password(password)
        if not is_valid:
            return JsonResponse({'error': message}, status=400)

        hashed_password = hash_password(password)
        connection = get_db_connection()

        if not connection:
            return JsonResponse({'error': 'Database connection failed'}, status=500)

        try:
            cursor = connection.cursor()

            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return JsonResponse({'error': 'Email already exists'}, status=400)

            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                (first_name, last_name, email, hashed_password)
            )
            connection.commit()
            return JsonResponse({'message': 'User registered successfully'}, status=201)

        except Exception as e:
            print("Signup error:", e)
            traceback.print_exc()
            return JsonResponse({'error': 'An error occurred during registration'}, status=500)

        finally:
            try:
                if cursor:
                    cursor.close()
            except:
                pass
            try:
                if connection:
                    connection.close()
            except:
                pass

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        print("Signup outer error:", e)
        traceback.print_exc()
        return JsonResponse({'error': 'An unexpected error occurred'}, status=500)


# Signin API (Traditional sign-in with email and password)
@csrf_exempt
def signin_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    if not check_rate_limit(request, 'signin'):
        return JsonResponse({'error': 'Too many login attempts. Please try again later.'}, status=429)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not all([email, password]):
            return JsonResponse({'error': 'Email and password are required'}, status=400)

        connection = get_db_connection()
        if not connection:
            return JsonResponse({'error': 'Database connection failed'}, status=500)

        try:
            cursor = connection.cursor(DictCursor)  # Use DictCursor for dictionary-style results
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not verify_password(password, user['password']):
                return JsonResponse({'error': 'Invalid credentials'}, status=401)

            cursor.execute(
                "UPDATE users SET failed_login_attempts = 0, last_login = %s WHERE id = %s",
                (datetime.now(), user['id'])
            )
            connection.commit()

            user_data = {
                'id': user['id'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'created_at': user['created_at'].isoformat() if user['created_at'] else None,
                'last_login': datetime.now().isoformat()
            }

            return JsonResponse({'message': 'Login successful', 'user': user_data}, status=200)

        except Exception as e:
            print("Signin error:", e)
            traceback.print_exc()
            return JsonResponse({'error': 'An error occurred during login'}, status=500)

        finally:
            try:
                if cursor:
                    cursor.close()
            except:
                pass
            try:
                if connection:
                    connection.close()
            except:
                pass

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        print("Signin outer error:", e)
        traceback.print_exc()
        return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.environ.get('OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('OAUTH_CLIENT_SECRET'),
    access_token_url=os.environ.get('OAUTH_TOKEN_URL'),
    authorize_url=os.environ.get('OAUTH_AUTHORIZE_URL'),
    api_base_url=os.environ.get('OAUTH_API_BASE_URL'),
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',  # Ensures refresh_token is returned
        'access_type': 'offline'
    },
)

def oauth_login(request):
    """Generate Google OAuth URL and return for frontend redirection"""
    try:
        redirect_uri = request.build_absolute_uri(os.environ.get('OAUTH_REDIRECT_URI'))
        authorization_url, state = oauth.google.authorize_url(
            redirect_uri=redirect_uri,
            access_type='offline',
            prompt='consent'
        )
        return JsonResponse({
            'authorization_url': authorization_url,
            'state': state,
            'expires_in': 3600  # Google's default access_token lifetime
        })

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({'error': 'OAuth initiation failed'}, status=500)


def oauth_callback(request):
    try:
        # 1. Exchange auth code for tokens
        token = oauth.google.fetch_token(
            os.environ.get('OAUTH_TOKEN_URL'),
            authorization_response=request.build_absolute_uri(),
            client_secret=os.environ.get('OAUTH_CLIENT_SECRET')
        )

        # 🧾 Print token details
        print("OAuth Callback - Access Token:", token.get('access_token'))
        print("OAuth Callback - Refresh Token:", token.get('refresh_token'))
        print("OAuth Callback - Expires In:", token.get('expires_in'))

        # 2. Get user info (optional)
        user_info = oauth.google.get(os.environ.get('OAUTH_USERINFO_URL'), token=token).json()

        # 3. Prepare response (minimal user data in JSON)
        response = JsonResponse({
            'message': 'Login successful',
            'user': {
                'email': user_info.get('email'),
                'name': user_info.get('name')
                # Never include sensitive data here!
            }
        })

        # 4. Set PRODUCTION-READY cookies
        cookie_settings = {
            'httponly': True,  # Block XSS attacks
            'secure': True,     # HTTPS-only (enforced in production)
            'samesite': 'Lax',  # Balance security vs usability
            'path': '/',        # Accessible across all paths
            'domain': '.yourdomain.com',  # Adjust for your domain
        }

        # Access token
        response.set_cookie(
            key='access_token',
            value=token['access_token'],
            max_age=token['expires_in'],
            **cookie_settings
        )

        # Refresh token (if available)
        if token.get('refresh_token'):
            response.set_cookie(
                key='refresh_token',
                value=token['refresh_token'],
                max_age=30 * 24 * 60 * 60,  # 30 days
                path='/auth/',  # Restrict path for security
                **cookie_settings
            )

        # ✅ Print before returning response
        print("OAuth Callback - Returning tokens in cookies.")
        return response

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({'error': 'Authentication failed'}, status=500)


def refresh_token(request):
    """Obtain new access token using refresh token"""
    try:
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode)
        
        refresh_token_value = data.get('refresh_token')
        
        if not refresh_token_value:
            return JsonResponse({'error': 'Refresh token required'}, status=400)

        # Refresh the token
        new_token = oauth.google.refresh_token(
            os.environ.get('OAUTH_TOKEN_URL'),
            refresh_token=refresh_token_value,
            client_id=os.environ.get('OAUTH_CLIENT_ID'),
            client_secret=os.environ.get('OAUTH_CLIENT_SECRET')
        )

        expires_at = datetime.now() + timedelta(seconds=new_token['expires_in'])

        # 🧾 Print new token details
        print("Token Refresh - New Access Token:", new_token.get('access_token'))
        print("Token Refresh - Expires In:", new_token.get('expires_in'))

        # ✅ Print before returning response
        print("Token Refresh - Returning new token response.")
        return JsonResponse({
            'access_token': new_token['access_token'],
            'expires_at': expires_at.isoformat(),
            'token_type': new_token['token_type']
        })

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({'error': 'Token refresh failed'}, status=401)

# Example simple Login API
@csrf_exempt
def LoginApi_View(request):
    return JsonResponse({"message": "Login API success"}, status=200)
