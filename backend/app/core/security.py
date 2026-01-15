from jose import jwt
from app.core.config import settings
import secrets
from passlib.context import CryptContext 
from datetime import datetime , timedelta


pwd_context = CryptContext(schemes=["bcrypt"] , deprecated="auto")

def hash_password(password :str) -> str :
    return pwd_context.hash(password)

def verify_password(plain_password:str , hashed_password:str)-> bool :
    return pwd_context.verify(plain_password , hashed_password)

def create_access_token(user_id : int):
    payload = {
        "sub" : str(user_id) ,
        "exp" : datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    }

    return jwt.encode(payload , settings.SECRET_KEY , algorithm=settings.ALGORITHM)

def create_refresh_token():
    return secrets.token_urlsafe(32)

def decode_token(token : str) :
    return jwt.decode(token , settings.SECRET_KEY , algorithms=[settings.ALGORITHM])

