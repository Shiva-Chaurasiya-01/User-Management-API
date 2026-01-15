from fastapi import Depends, HTTPException, APIRouter, status
from sqlalchemy.orm.session import SessionTransactionState
from app.core.security import *
from app.schemas.auth import *
from sqlmodel import SQLModel, Session, select
from datetime import datetime, timedelta
from app.db.session import get_session
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.api.depe import get_current_user
from app.core.config import settings


router = APIRouter(prefix="/auth", tags=["Authorization"])


@router.post("/signup")
def signup(user: SignupRequest, session: Session = Depends(get_session)):
    statement = select(User).where(User.email == user.email)

    existing_user = session.exec(statement).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exist"
        )

    db_user = User(
        email= user.email,
        hashed_password=hash_password(user.password),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@router.post("/login", response_model=TokenResponse)
def login(user: LoginRequest, session: Session = Depends(get_session)):
    statement = select(User).where(User.email == user.email)

    db_user = session.exec(statement).first()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Credentials"
        )

    access = create_access_token(db_user.id)
    refresh = create_refresh_token()

    rt = RefreshToken(
        user_id=db_user.id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow()
        + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        token=refresh,
    )

    session.add(rt)
    session.commit()

    return {"access_token": access, "refresh_token": refresh}


@router.post("/refresh")
def refresh_token(data: RefreshRequest, session: Session = Depends(get_session)):

    statement = select(RefreshToken).where(
        RefreshToken.token == data.refresh_token, RefreshToken.is_revoked == False
    )

    token = session.exec(statement).first()

    if not token or token.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Refresh Token"
        )

    access = create_access_token(token.user_id)
    return {"access_token": access}


@router.post("/logout")
def logout(data: RefreshRequest, session: Session = Depends(get_session)):

    statement = select(RefreshToken).where(RefreshToken.token == data.refresh_token)

    token = session.exec(statement).first()

    if token:
        token.is_revoked = True
        session.add(token)
        session.commit()

    return {"message": "Logged out"}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/change_password")
def change_password(
    data: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):

    if not verify_password(data.old_password, user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Wrong Password")

    user.hashed_password = hash_password(data.new_password)

    user.updated_at = datetime.utcnow()
    session.add(user)
    session.commit()
    return {"message": "Password updated"}
