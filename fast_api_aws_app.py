from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
import boto3
from pydantic import BaseModel
from typing import List
import bcrypt

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

# Define Pydantic models
class CookiePreferences(BaseModel):
    marketing: bool
    performance: bool

class User(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str

class DataPreferences(BaseModel):
    statement: str
    anonymity: str
    recipient: str
    purpose: str

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Replace with your region
users_table = dynamodb.Table('Users')
cookie_preferences_table = dynamodb.Table('CookiePreferences')
data_preferences_table = dynamodb.Table('DataPreferences')

# Helper function to hash passwords
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

# Helper function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Create Account Endpoint
@app.post("/createAccount")
def sign_up(user: User):
    try:
        # Check if user already exists
        response = users_table.get_item(Key={'email': user.email})
        if 'Item' in response:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists",
            )

        # Hash the password before storing
        hashed_password = hash_password(user.password)

        # Add user to DynamoDB
        users_table.put_item(Item={
            'email': user.email,
            'firstname': user.firstname,
            'lastname': user.lastname,
            'password': hashed_password
        })
        return {"message": f"User {user.email} registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# Helper function to authenticate the user
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    try:
        # Retrieve user credentials from the DynamoDB Users table
        response = users_table.get_item(Key={'email': credentials.username})
        user = response.get('Item')

        if user is None or not verify_password(credentials.password, user['password']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to server error"
        )

# Set Cookie Preferences
@app.post("/cookiePreferences/{site}")
def set_cookie_preferences(site: str, consent: CookiePreferences, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    try:
        # Update user cookie preferences in DynamoDB
        response = cookie_preferences_table.update_item(
            Key={'email': user['email']},
            UpdateExpression="SET #site = :val",
            ExpressionAttributeNames={"#site": site},
            ExpressionAttributeValues={":val": consent.model_dump()},
            ReturnValues="UPDATED_NEW"
        )
        return {"message": f"Cookie preferences set successfully for user {user['email']} for site {site}"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# Get Cookie Preferences
@app.get("/cookiePreferences/{site}")
def get_cookie_preferences(site: str, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    try:
        response = cookie_preferences_table.get_item(Key={'email': user['email']})
        if 'Item' not in response:
            raise HTTPException(status_code=404, detail="No preferences data found for user")
        return response['Item'].get(site, {})
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# Set Data Preferences
@app.post("/dataPreferences")
def set_data_preferences(preferences: DataPreferences, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    try:
        # Update user data preferences in DynamoDB
        data_preferences_table.put_item(Item={
            'email': user['email'],
            'statement': preferences.statement,
            'anonymity': preferences.anonymity,
            'recipient': preferences.recipient,
            'purpose': preferences.purpose
        })
        return {"message": "Data preferences set successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# Get Data Preferences
@app.get("/dataPreferences")
def get_data_preferences(credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    try:
        response = data_preferences_table.get_item(Key={'email': user['email']})
        if 'Item' not in response:
            raise HTTPException(status_code=404, detail="No data preferences found for user")
        return response['Item']
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
