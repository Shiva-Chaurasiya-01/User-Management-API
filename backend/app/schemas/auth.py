import email
from pydantic import BaseModel  ,EmailStr
from typing import Optional

from app.models import refresh_token 

class SignupRequest(BaseModel):
    email : EmailStr
    password : str 

class LoginRequest(BaseModel):
    email : EmailStr
    password : str 

class TokenResponse(BaseModel):
    access_token : str 
    refresh_token : str 
    token_type : str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token : str 

class ChangePasswordRequest(BaseModel):
    old_password : str 
    new_password : str 
