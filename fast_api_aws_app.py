from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import boto3
from pydantic import BaseModel
from typing import List, Literal
import bcrypt
from botocore.exceptions import NoCredentialsError
import os
import json
import uuid
from datetime import date, datetime, time, timedelta

'''
RUN FOR HEROKU-AWS INTEGRATION
heroku config:set AWS_ACCESS_KEY_ID=<>
heroku config:set AWS_SECRET_ACCESS_KEY=<>
heroku config:set AWS_REGION=<>
heroku config:set S3_BUCKET_NAME=<>
'''

app = FastAPI()
security = HTTPBasic()

origins = [
    "https://papayaverse.github.io",  # Frontend domain
    "http://localhost:8000",  # Local development (if applicable)
    "http://127.0.0.1:8000"  # Local development
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_methods=["*"],  
    allow_headers=["*"],  
    allow_credentials=True,
)

app.sessions = {}

# Define Pydantic models

# CookiePreferences
'''
{
    "allow_marketing": true,
    "allow_performance": true
}
'''
class CookiePreferences(BaseModel):
    allow_marketing: bool
    allow_performance: bool

# User
'''
{
    "firstname": "John",
    "lastname": "Doe",
    "email": "johndoe@something.com",
    "password": "password"
'''
class User(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str

# DataPreferences
'''
{
    "statement": "I am willing to share data with multiple options.",
    "anonymity": "de-anonymized"
    "recipient": ["advertisers", "retailers"],
    "purpose": ["targeted advertising", "market research"]
}
'''

class DataPreferences(BaseModel):
    statement: str
    anonymity: Literal["anonymized", "de-anonymized"]  # Only allows "anonymized" or "de-anonymized"
    recipient: List[str]  # List of strings for multiple recipients
    purpose: List[str]    # List of strings for multiple purposes

class DataBrowsing(BaseModel):
    url: str
    website: str
    title: str
    browseDate: date

# Initialize S3 client
s3 = boto3.client(
    's3',
    region_name=os.getenv('AWS_REGION'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)
BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

# Helper function to store dictionaries(JSON) in S3
def upload_file_to_s3(file_name, file_content):
    try:
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=file_name,
            Body=file_content,
            ContentType='application/json'  # Set the appropriate content type
        )
        return {"message": f"File {file_name} uploaded successfully to S3"}
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="AWS credentials not configured")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Helper function to retrieve dictionaries(JSON) from S3
def download_file_from_s3(file_name):
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=file_name)
        file_content = response['Body'].read().decode('utf-8')
        return file_content
    except s3.exceptions.NoSuchKey:
        raise HTTPException(status_code=404, detail="File not found in S3")
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="AWS credentials not configured")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Helper function to delete dictionaries(JSON) from S3
def delete_file_from_s3(file_name):
    try:
        s3.delete_object(Bucket=BUCKET_NAME, Key=file_name)
        return {"message": f"File {file_name} deleted successfully from S3"}
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="AWS credentials not configured")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Helper function to hash passwords
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

# Helper function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# SIGN UP ENDPOINT
@app.post("/createAccount")
def sign_up(user: User):
    # Check if the user already exists in S3
    try:
        download_file_from_s3(f'users/{user.email}.json')
        # If no exception, the user already exists
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this Email already exists",
        )
    except HTTPException as e:
        if e.status_code != 404:
            raise e  # Raise any other exceptions apart from 'not found'
    
    # Hash the password before storing
    hashed_password = hash_password(user.password)
    new_user = {
        "firstname": user.firstname,
        "lastname": user.lastname,
        "email": user.email,
        "password": hashed_password
    }
    
    # Save the new user to S3
    user_json = json.dumps(new_user)
    upload_file_to_s3(f'users/{user.email}.json', user_json)
    
    return {"message": f"User {user.email} registered successfully"}

# AUTHENTICATION HELPER
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    # Retrieve the user data from S3
    try:
        user_data_json = download_file_from_s3(f'users/{credentials.username}.json')
        user_data = json.loads(user_data_json)
    except HTTPException as e:
        if e.status_code == 404:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )
        else:
            raise e
    
    # Verify password
    if not verify_password(credentials.password, user_data["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user_data

# Helper function to create a session in which we can store state about the user
def create_session(user_email: str):
    session_id = str(len(app.sessions))
    app.sessions[session_id] = {"user_email": user_email}
    return session_id

# Helper function to get user_id from the session
def get_user_from_session(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id and session_id in app.sessions:
        return app.sessions[session_id]["user_email"]
    return None

def generate_anonymous_id():
    return str(uuid.uuid4())

# LOGIN ENDPOINT
@app.post("/login")
def login(user: User = Depends(authenticate_user)):
    # Create a session for the authenticated user
    session_id = create_session(user["email"])
    return {"message": f"User {user['email']} Logged in successfully", "session_id": session_id}

# COLLECTING COOKIE PREFERENCES
@app.post("/cookiePreferences")
def set_cookie_preferences(
    cookie_preferences: CookiePreferences, 
    identifier: str = None  # Optional parameter to associate with a logged-in user or anonymous ID
):
    # Use the provided identifier or generate an anonymous ID if not provided

    #identifier = identifier if identifier else generate_anonymous_id()
    if identifier is None or identifier == "null" or identifier == "":
        identifier = generate_anonymous_id()
    # Save preferences to S3
    file_name = f'cookie_preferences/{identifier}.json'
    preferences_json = json.dumps(cookie_preferences.model_dump())
    upload_file_to_s3(file_name, preferences_json)
    
    return {"message": f"Cookie preferences saved successfully for {identifier}", "id": identifier}

# COLLECTING DATA PREFERENCES
@app.post("/dataPreferences")
def set_data_preferences(
    data_preferences: DataPreferences, 
    identifier: str = None  # Optional parameter to associate with a logged-in user or anonymous ID
):
    # Use the provided identifier or generate an anonymous ID if not provided

    #identifier = identifier if identifier else generate_anonymous_id()
    if identifier is None or identifier == "null" or identifier == "":
        identifier = generate_anonymous_id()
    # Save preferences to S3
    file_name = f'data_preferences/{identifier}.json'
    preferences_json = json.dumps(data_preferences.model_dump())
    upload_file_to_s3(file_name, preferences_json)
    
    return {"message": f"Data preferences saved successfully for {identifier}", "id": identifier}

# COLLECTING DATA PREFERENCES
@app.post("/dataBrowsing")
def set_data_browsing(
    data: DataBrowsing, 
    identifier: str = None  # Optional parameter to associate with a logged-in user or anonymous ID
):
    # Use the provided identifier or generate an anonymous ID if not provided

    #identifier = identifier if identifier else generate_anonymous_id()
    if identifier is None or identifier == "null" or identifier == "":
        identifier = generate_anonymous_id()
    file_identifier = generate_anonymous_id()
    # Save preferences to S3
    file_name = f'data_browsing/{identifier}/{file_identifier}.json'
    data_json = json.dumps(data.model_dump())
    upload_file_to_s3(file_name, data_json)
    return {"message": f"Data browsing saved successfully for {identifier}", "id": identifier}