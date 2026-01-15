from sqlmodel import Session
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from app.db.session import get_session
from app.models.user import User
from app.core.security import decode_token


oauth2_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
):

    token = credentials.credentials
    print(token)
    
    payload = decode_token(token)
    user_id = int(payload.get("sub"))

    # except JWTError: 
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bhosda"
    #     )

    user = session.get(User, user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive"
        )

    return user
