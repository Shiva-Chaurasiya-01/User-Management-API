from fastapi import FastAPI 
from app.api.auth import router as auth_router
from app.db.session import engine
from sqlmodel import SQLModel
from app.models.refresh_token import RefreshToken
from app.models.user import User

app = FastAPI()


@app.on_event("startup")
def onStartup():
    SQLModel.metadata.create_all(engine)

app.include_router(auth_router)

@app.get("/")
def root():
    return {"message" : "Backend is running"}