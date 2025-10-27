from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import logging, time, traceback

# ---- CONFIG ----
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600

logging.basicConfig(level=logging.INFO)

app = FastAPI()

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- DB ----
SQLALCHEMY_DATABASE_URL = "postgresql://fastapi_auth_db_0jjf_user:hPi8Cl80ESARCamjXQ4CPXSH9DsP0xcX@dpg-d3uo262li9vc73c8di50-a.oregon-postgres.render.com/fastapi_auth_db_0jjf"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

# ---- AUTH ----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_in=ACCESS_TOKEN_EXPIRE_SECONDS):
    to_encode = data.copy()
    to_encode.update({"exp": time.time() + expires_in})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logging.info(f"JWT created for {data.get('sub')}")
    return token

# ---- SCHEMAS ----
class UserCreate(BaseModel):
    username: str
    password: str

# ---- ROUTES ----
@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db), request: Request = None):
    logging.info(f"Register request: username={user.username}, len(password)={len(user.password)}")
    try:
        if len(user.password.encode('utf-8')) > 72:
            logging.warning("⚠️ Password too long (>72 bytes) - bcrypt will fail!")
            raise HTTPException(status_code=400, detail="Password too long (max 72 bytes).")

        existing = db.query(User).filter(User.username == user.username).first()
        if existing:
            logging.warning(f"❌ Username already exists: {user.username}")
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed = pwd_context.hash(user.password)
        new_user = User(username=user.username, hashed_password=hashed)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logging.info(f"✅ User {user.username} registered successfully")
        return {"message": "User created successfully"}

    except Exception as e:
        logging.error(f"Register error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logging.info(f"Login attempt: username={form_data.username}")
    try:
        user = db.query(User).filter(User.username == form_data.username).first()
        if not user:
            logging.warning("❌ User not found")
            raise HTTPException(status_code=400, detail="Invalid credentials")

        if not pwd_context.verify(form_data.password, user.hashed_password):
            logging.warning("❌ Incorrect password")
            raise HTTPException(status_code=400, detail="Invalid credentials")

        token = create_access_token({"sub": user.username})
        logging.info(f"✅ Login success for {user.username}")
        return {"access_token": token, "token_type": "bearer"}

    except Exception as e:
        logging.error(f"Login error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.get("/db-test")
def db_test(db: Session = Depends(get_db)):
    count = db.query(User).count()
    logging.info(f"DB test endpoint hit. User count: {count}")
    return {"user_count": count}
