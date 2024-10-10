from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import boto3
from pydantic import BaseModel
from typing import List, Literal
import bcrypt
from botocore.exceptions import NoCredentialsError
import os
import json

'''
RUN FOR HEROKU-AWS INTEGRATION
heroku config:set AWS_ACCESS_KEY_ID=<your-access-key-id>
heroku config:set AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
heroku config:set AWS_REGION=<your-aws-region>
heroku config:set S3_BUCKET_NAME=my-payback-data-bucket
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

# LOGIN ENDPOINT
@app.post("/login")
def login(user: User = Depends(authenticate_user)):
    # Create a session for the authenticated user
    session_id = create_session(user["email"])
    return {"message": f"User {user['email']} Logged in successfully", "session_id": session_id}