from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import random
from fastapi import Request
from fastapi import Body
from pydantic import BaseModel

app = FastAPI()
security = HTTPBasic()

class ConsentPreferences(BaseModel):
    marketing: bool
    performance: bool
    sell_data: bool

class User(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str

app.users = {'ram@papayaverse.com' : User(firstname='Ram', lastname='Test', email='ram@papayaverse.com', password='password')}
app.user_consent_preferences = {'ram@papayaverse.com' : {'default': ConsentPreferences(marketing=False, performance=True, sell_data=False)}}

app.sessions = {}

@app.get('/hello')
def hello():
    return {"hello" : "world!"}

@app.get('/hello/{personName}')
def hello_person(personName):
    return {"hello" : personName}

# Create Account Endpoint
@app.post("/createAccount")
def sign_up(user: User):
    user_in_db = app.users.get(user.email)
    if user_in_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this Email already exists",
        )
    app.users[user.email] = user
    return {"message": f"User {user.email} registered successfully"}

# Helper function to create a session in which we can store state about the user
def create_session(user_email: str):
    session_id = str(len(app.sessions))# + random.randint(0, 1000))
    app.sessions[session_id] = {"user_email": user_email}
    return session_id

# Helper function to authenticate the User
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = app.users.get(credentials.username) # we get the user based on their email id
    if user is None or user.password != credentials.password:
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

# Helper to get user from session_id
def get_authenticated_user_from_session_id(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id is None or session_id not in app.sessions:
        raise HTTPException(
            status_code=401,
            detail="Invalid session ID",
        )
    # Get the user from the session
    user = app.users[app.sessions[session_id]["user_email"]]
    return user

# Endpoint to get site preferences
@app.get("/preferences/{site}")
def prefs(site: str, user: User = Depends(get_authenticated_user_from_session_id)):
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated")
    elif user.email not in app.user_consent_preferences:
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
def prefs(site: str, consent: ConsentPreferences, user: User = Depends(get_authenticated_user_from_session_id)):
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated")
    else :
        if user.email not in app.user_consent_preferences:
            app.user_consent_preferences[user.email] = {}
        app.user_consent_preferences[user.email][site] = consent
        return {"message": f"Set preferences successfully for user {user.email} for site {site}"}