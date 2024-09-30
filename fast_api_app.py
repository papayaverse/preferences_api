from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import random
from fastapi import Request
from fastapi import Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import base64
import json
import boto3
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
    allow_origins=origins,  # Set to ["*"] to allow all origins, but be careful with security
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
    allow_credentials=True,
)

class ConsentPreferences(BaseModel):
    marketing: bool
    performance: bool
    sell_data: bool

class User(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str

class CollectedData(BaseModel):
    url: str
    title: str
    timestamp: str

class DataPreferences(BaseModel):
    statement: str
    anonymity: str
    recipient: str
    purpose: str

# Initialize DynamoDB
#dynamodb = boto3.resource('dynamodb', region_name='us-east-2')  # Replace with your region

app.users = {'ram@papayaverse.com' : User(firstname='Ram', lastname='Test', email='ram@papayaverse.com', password='password')}
app.user_consent_preferences = {'ram@papayaverse.com' : {'default': ConsentPreferences(marketing=False, performance=True, sell_data=False)}}
app.sessions = {}
app.collected_data = {}
app.data_preferences = []

# Helper function to hash passwords
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

# Helper function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

@app.get('/hello')
def hello():
    return {"hello": "world!"}

@app.get('/hello/{personName}')
def hello_person(personName):
    return {"hello": personName}

# Create Account Endpoint
@app.post("/createAccount")
def sign_up(user: User):
    user_in_db = app.users.get(user.email)
    hashed_password = hash_password(user.password)
    if user_in_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this Email already exists",
        )
    new_user = User(firstname=user.firstname, lastname=user.lastname, email=user.email, password=hashed_password)
    app.users[user.email] = new_user
    return {"message": f"User {user.email} registered successfully"}

# Helper function to create a session in which we can store state about the user
def create_session(user_email: str):
    session_id = str(len(app.sessions))
    app.sessions[session_id] = {"user_email": user_email}
    return session_id

# Helper function to authenticate the User
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = app.users.get(credentials.username)
    if user is None or (not verify_password(credentials.password, user.password)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

# Login endpoint
@app.post("/login")
def login(user: User = Depends(authenticate_user)):
    session_id = create_session(user.email)
    return {"message": f"User {user.email} Logged in successfully", "session_id": session_id}

# Custom dependency to handle both session ID and Authorization header
def get_authenticated_user(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    # Try to get user from session ID in cookies
    session_id = request.cookies.get("session_id")
    if session_id and session_id in app.sessions:
        user_email = app.sessions[session_id]["user_email"]
        user = app.users.get(user_email)
        if user:
            return user

    # Fallback to Authorization header if no valid session ID
    auth_header = request.headers.get("Authorization")
    if auth_header:
        auth_type, auth_credentials = auth_header.split()
        if auth_type.lower() == "basic":
            decoded_credentials = base64.b64decode(auth_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":")
            user = app.users.get(username)
            if user and user.password == password:
                return user

    # Raise an error if neither method succeeded
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )

# Endpoint to get site preferences
@app.get("/preferences/{site}")
def prefs(site: str, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    if user.email not in app.user_consent_preferences:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not have preferences yet")
    else:
        if site not in app.user_consent_preferences[user.email]:
            site = 'default' if 'default' in app.user_consent_preferences[user.email] else None
        if site is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user.email} does not have preferences for this site or default") 
        else:
            return app.user_consent_preferences[user.email][site]

# Endpoint to set site preferences
@app.post("/preferences/{site}")
def prefs(site: str, consent: ConsentPreferences, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    if user.email not in app.user_consent_preferences:
        app.user_consent_preferences[user.email] = {}
    app.user_consent_preferences[user.email][site] = consent
    return {"message": f"Set preferences successfully for user {user.email} for site {site}"}

# Endpoint to collect data
@app.post("/collect")
def collect_data(data: List[CollectedData], credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    if user.email not in app.collected_data:
        app.collected_data[user.email] = []
    app.collected_data[user.email] += data
    return {"message": "Data collected successfully"}

# Endpoint to retrieve collected data (for testing purposes)
@app.get("/data")
def get_data(credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    if user.email not in app.collected_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No data collected for this user")
    return app.collected_data[user.email]

# Get all data
@app.get("/alldata")
def get_data(credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    if user.email == 'ram@papayaverse.com':
        return app.collected_data
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to view this data")
    
# Post preferences data
@app.post("/preferencesData")
def post_preferences_data(prefs: DataPreferences):
    # Convert prefs to a dictionary (use model_dump() if Pydantic v2, dict() if v1)
    prefs_dict = prefs.model_dump() if hasattr(prefs, 'model_dump') else prefs.dict()

    # Save preferences to a file (append to JSON file)
    try:
        with open('preferences.json', 'r+') as file:
            # Load existing data
            data = json.load(file)
            # Append new preferences
            data.append(prefs_dict)
            # Seek to the beginning of the file and overwrite with updated data
            file.seek(0)
            json.dump(data, file, indent=4)
    except FileNotFoundError:
        # If the file does not exist, create it and add the first preference
        with open('preferences.json', 'w') as file:
            json.dump([prefs_dict], file, indent=4)

    return {"message": "Data preferences saved successfully"}

# Endpoint to read all saved preferences
@app.get("/preferencesData")
def get_all_preferences():
    try:
        # Open the preferences file and read its content
        with open('preferences.json', 'r') as file:
            data = json.load(file)  # Load the JSON data from the file
            return data  # Return the data as JSON response
    except FileNotFoundError:
        # If the file doesn't exist, raise a 404 error
        raise HTTPException(status_code=404, detail="No preferences data found")
    except json.JSONDecodeError:
        # If the file is corrupted or invalid JSON, raise a 500 error
        raise HTTPException(status_code=500, detail="Error reading preferences data")