from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

import jwt
from jwt.exceptions import InvalidTokenError

from app.database import SessionLocal
from app.config import settings
from app.crud import user as user_crud
from app.schemas import user as user_schema

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.APP_SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except InvalidTokenError as exc:
        raise credentials_exception from exc
    user = await user_crud.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_super_admin_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user.is_super_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")
    return user


async def get_current_admin_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough privileges")
    return user
