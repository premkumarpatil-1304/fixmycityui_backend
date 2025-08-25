import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
from enum import Enum
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

# FastAPI app
app = FastAPI(title="Simple Civic Innovation API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL")
DB_NAME = os.getenv("MONGODB_NAME")  # ✅ matches .env

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# MongoDB client
mongo_client = None
db = None

class IdeaCategory(str, Enum):

    WASTE = "waste"
    POTHOLES = "potholes"  
    HEALTH = "health"
    TRANSPORT = "transport"
    PARKS = "parks"
    SAFETY = "safety"
    ENVIRONMENT = "environment"
    INFRASTRUCTURE = "infrastructure"

# PyObjectId for MongoDB _id handling
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

# Startup and shutdown events
@app.on_event("startup")
async def startup_db_client():
    global mongo_client, db
    mongo_client = AsyncIOMotorClient(MONGODB_URL)
    db = mongo_client[DB_NAME]
    
    # Create collections if they don't exist
    collections = await db.list_collection_names()
    if "users" not in collections:
        await db.create_collection("users")
        await db.users.create_index("email", unique=True)
    
    if "ideas" not in collections:
        await db.create_collection("ideas")
    
    # Add this for votes collection
    if "votes" not in collections:
        await db.create_collection("votes")
        await db.votes.create_index([("idea_id", 1), ("user_id", 1)], unique=True)


@app.on_event("shutdown")
async def shutdown_db_client():
    if mongo_client:
        mongo_client.close()

# Models
class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(ObjectId()))
    is_admin: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "id": "60d21b4667d0d8992e610c85",
                "email": "user@example.com",
                "full_name": "John Doe",
                "is_admin": False,
                "created_at": "2023-01-01T00:00:00"
            }
        }

class UserInDB(User):
    hashed_password: str

class IdeaBase(BaseModel):
    title: str
    description: str
    category: IdeaCategory  # Now validates against enum
    location: Optional[str] = None

class IdeaCreate(IdeaBase):
    pass

class Idea(IdeaBase):
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=2000)
    category: IdeaCategory
    location: Optional[str] = Field(None, max_length=200)
    id: str = Field(default_factory=lambda: str(ObjectId()))
    creator_id: str
    creator_name: str
    status: str = "OPEN"
    vote_score: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "id": "60d21b4667d0d8992e610c85",
                "title": "Improve City Parks",
                "description": "Add more benches and trees",
                "category": "ENVIRONMENT",
                "location": "Central Park",
                "creator_id": "60d21b4667d0d8992e610c85",
                "creator_name": "John Doe",
                "status": "OPEN",
                "vote_score": 0,
                "created_at": "2023-01-01T00:00:00"
            }
        }

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_user(email: str):
    user = await db.users.find_one({"email": email})
    if user:
        user["id"] = str(user["_id"])
        return UserInDB(**user)

async def authenticate_user(email: str, password: str):
    user = await get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Auth routes
@app.post("/api/auth/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/register", response_model=User)
async def register_user(user: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_data = user.dict()
    user_data.pop("password")
    user_data["hashed_password"] = hashed_password
    user_data["created_at"] = datetime.utcnow()
    user_data["is_admin"] = False
    
    result = await db.users.insert_one(user_data)
    created_user = await db.users.find_one({"_id": result.inserted_id})
    created_user["id"] = str(created_user["_id"])
    
    return User(**created_user)

# User routes
@app.get("/api/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Idea routes
@app.post("/api/ideas/", response_model=Idea)
async def create_idea(idea: IdeaCreate, current_user: User = Depends(get_current_user)):
    idea_data = idea.dict()
    idea_data["creator_id"] = str(current_user.id)
    idea_data["creator_name"] = current_user.full_name
    idea_data["created_at"] = datetime.utcnow()
    idea_data["status"] = "OPEN"
    idea_data["vote_score"] = 0
    
    result = await db.ideas.insert_one(idea_data)
    created_idea = await db.ideas.find_one({"_id": result.inserted_id})
    created_idea["id"] = str(created_idea["_id"])
    
    return Idea(**created_idea)

@app.get("/api/ideas/", response_model=List[Idea])
async def read_ideas(skip: int = 0, limit: int = 10):
    ideas = []
    cursor = db.ideas.find().skip(skip).limit(limit)
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        ideas.append(Idea(**doc))
    return ideas

@app.get("/api/ideas/{idea_id}", response_model=Idea)
async def read_idea(idea_id: str):
    idea = await db.ideas.find_one({"_id": ObjectId(idea_id)})
    if idea is None:
        raise HTTPException(status_code=404, detail="Idea not found")
    idea["id"] = str(idea["_id"])
    return Idea(**idea)

@app.post("/api/ideas/{idea_id}/vote")
async def vote_on_idea(
    idea_id: str, 
    vote_type: str,  # "upvote" or "downvote"
    current_user: User = Depends(get_current_user)
):
    if vote_type not in ["upvote", "downvote"]:
        raise HTTPException(status_code=400, detail="Invalid vote type")
    
    # Check if user already voted
    existing_vote = await db.votes.find_one({
        "idea_id": idea_id, 
        "user_id": current_user.id
    })
    
    vote_change = 1 if vote_type == "upvote" else -1
    
    if existing_vote:
        # Update existing vote
        old_vote = 1 if existing_vote["vote_type"] == "upvote" else -1
        if old_vote != vote_change:
            await db.votes.update_one(
                {"_id": existing_vote["_id"]},
                {"$set": {"vote_type": vote_type}}
            )
            # Update idea score (+2 or -2 for vote flip)
            await db.ideas.update_one(
                {"_id": ObjectId(idea_id)},
                {"$inc": {"vote_score": vote_change - old_vote}}
            )
    else:
        # New vote
        await db.votes.insert_one({
            "idea_id": idea_id,
            "user_id": current_user.id,
            "vote_type": vote_type,
            "created_at": datetime.utcnow()
        })
        await db.ideas.update_one(
            {"_id": ObjectId(idea_id)},
            {"$inc": {"vote_score": vote_change}}
        )
    
    return {"status": "success", "message": f"Successfully {vote_type}d"}



@app.delete("/api/ideas/{idea_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_idea(idea_id: str, current_user: User = Depends(get_current_user)):
    # Check if idea exists and user is the creator
    existing_idea = await db.ideas.find_one({"_id": ObjectId(idea_id)})
    if existing_idea is None:
        raise HTTPException(status_code=404, detail="Idea not found")
    if str(existing_idea["creator_id"]) != str(current_user.id) and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this idea")
    
    # Delete idea
    await db.ideas.delete_one({"_id": ObjectId(idea_id)})
    
    return {"status": "success"}

# Health check endpoint
@app.get("/api/health")
async def health_check():
    return {"status": "ok"}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)