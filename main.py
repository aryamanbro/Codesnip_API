from enum import Enum
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List, Optional, Annotated
from sqlmodel import SQLModel, Field, Session, select
from database import get_session, create_db_and_tables
from config import settings
from fastapi.middleware.cors import CORSMiddleware
from pwdlib import PasswordHash

from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm



class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str

class UserCreate(BaseModel):
    email: str
    password: str

class UserRead(BaseModel):
    id: int
    email: str

class Language(str, Enum):
    python = "Python"
    javascript = "JavaScript"
    java = "Java"
    csharp = "C#"
    ruby = "Ruby"

class SnippetBase(BaseModel):
    title: str
    code: str
    language: Language = Language.python
    linenos: bool = False

class SnippetCreate(SnippetBase):
    pass

class SnippetUpdate(BaseModel):
    title: Optional[str] = None
    code: Optional[str] = None
    language: Optional[Language] = None
    linenos: Optional[bool] = None

class Snippet(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    code: str
    owner_id: int = Field(foreign_key="user.id")
    language: Language = Language.python
    linenos: bool = False

class SnippetRead(SnippetBase):
    id: int
    owner_id: int


password_hash = PasswordHash.recommended()

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




app = FastAPI()

origins = [
    "http://localhost:5173",
    "https://codesnip-frontend-taupe.vercel.app" 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,      
    allow_credentials=True,
    allow_methods=["*"],        
    allow_headers=["*"],        
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)]
) -> User:
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
        
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DBSession = Annotated[Session, Depends(get_session)]



@app.post("/users/", response_model=UserRead)
def create_user(user: UserCreate, session: DBSession):
    existing_user = session.exec(select(User).where(User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_pass = hash_password(user.password)
    db_user = User(email=user.email, hashed_password=hashed_pass)
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    
    return db_user

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: DBSession
):
    
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
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


@app.get("/users/me", response_model=UserRead)
async def read_users_me(current_user: CurrentUser):
    return current_user

@app.get("/")
async def read_root():
    return {"CodeSnip": "Save Your Important Snippets!"}



@app.get("/snippets/", response_model=List[SnippetRead])
async def read_snippets(
    current_user: CurrentUser,
    session: DBSession,
    snippet_id: int | None = None, 
    language: Language | None = None,
):
    
    query = select(Snippet).where(Snippet.owner_id == current_user.id)
    
    if language is not None:
        query = query.where(Snippet.language == language)
    if snippet_id is not None:
        query = query.where(Snippet.id == snippet_id)
        
    results = session.exec(query).all()
    
    
    return results


@app.post("/snippets/", response_model=SnippetRead)
def create_snippet(
    snippet: SnippetCreate,
    current_user: CurrentUser,
    session: DBSession
):
    # 1. Convert the input Pydantic model to a dictionary
    snippet_data = snippet.model_dump()

    # 2. Add the owner_id from our logged-in user
    snippet_data["owner_id"] = current_user.id

    # 3. Now, validate the *complete* dictionary against the Snippet DB model
    db_snippet = Snippet.model_validate(snippet_data)

    # 4. Save to the database
    session.add(db_snippet)
    session.commit()
    session.refresh(db_snippet)
    return db_snippet

@app.put("/snippets/{snippet_id}", response_model=SnippetRead)
async def update_snippet(
    snippet_id: int,
    snippet: SnippetUpdate,
    current_user: CurrentUser,
    session: DBSession
):
    db_snippet = session.get(Snippet, snippet_id)
    
    if not db_snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")
    
    

    if db_snippet.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to edit this snippet")
    
    snippet_data = snippet.model_dump(exclude_unset=True)
    for key, value in snippet_data.items():
        setattr(db_snippet, key, value)
    
    session.add(db_snippet)
    session.commit()
    session.refresh(db_snippet)
    return db_snippet



@app.delete("/snippets/{snippet_id}")
async def delete_snippet(
    snippet_id: int,
    current_user: CurrentUser,
    session: DBSession
):
    db_snippet = session.get(Snippet, snippet_id)
    
    if not db_snippet:
        raise HTTPException(status_code=404, detail="Snippet not found")
    
    
    if db_snippet.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this snippet")
        
    session.delete(db_snippet)
    session.commit()
    return {"message": f"Snippet {snippet_id} deleted"}



@app.delete("/snippets/by-language/{language}", response_model=List[SnippetRead])
async def delete_snippet_by_language(
    language: Language,
    current_user: CurrentUser,
    session: DBSession
):
    
    query = select(Snippet).where(
        Snippet.language == language,
        Snippet.owner_id == current_user.id
    )
    db_snippets = session.exec(query).all()

    if not db_snippets:
        raise HTTPException(status_code=404, detail="No snippets found for this language")
    
    for db_snippet in db_snippets:
        session.delete(db_snippet)
        
    session.commit()
    return db_snippets
