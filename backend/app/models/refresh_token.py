from sqlmodel import SQLModel , Field , Session, sql 
from datetime import datetime
from typing import Optional

class RefreshToken(SQLModel , table=True):
    id : Optional[int] = Field(default=None, primary_key=True)
    user_id : int = Field(foreign_key="user.id" , index=True)
    token : str = Field(unique=True)
    is_revoked : bool = False
    created_at : datetime 
    expires_at : datetime 
