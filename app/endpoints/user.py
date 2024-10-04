from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import UUID4
from app.models import user as user_model
from app.crud import user as user_crud
from app.schemas import user as user_schema
from app.dependencies import get_current_user, get_db, get_current_admin_user
from app.logger import get_logger

import bcrypt
import logging

logger = get_logger(__name__)


router = APIRouter()


@router.post(
    "/", response_model=user_schema.User, dependencies=[Depends(get_current_admin_user)]
)
async def create_user(
    user: user_schema.UserCreate,
    db: Session = Depends(get_db),
):
    db_user = await user_crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())
    return await user_crud.create_user(
        db=db, user=user, hashed_password=hashed_password.decode("utf-8")
    )


@router.get("/me/", response_model=user_schema.User)
async def read_users_me(current_user: user_schema.User = Depends(get_current_user)):
    return current_user


@router.get(
    "/",
    response_model=list[user_schema.User],
    dependencies=[Depends(get_current_admin_user)],
)
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    return await user_crud.get_users(db, skip=skip, limit=limit)


@router.get(
    "/{user_id}/",
    response_model=user_schema.User,
    dependencies=[Depends(get_current_admin_user)],
)
async def read_user(
    user_id: UUID4,
    db: Session = Depends(get_db),
):
    db_user = await user_crud.get_user(db, user_id=user_id)
    return db_user


@router.patch("/update-password/", response_model=user_schema.User)
async def update_password(
    password: user_schema.UserPasswordUpdate,
    db: Session = Depends(get_db),
    current_user: user_schema.User = Depends(get_current_user),
):
    logger.info("Hello there")
    user_id = current_user.id
    current_password = password.current_password
    new_password = password.new_password
    if current_password == new_password:
        raise HTTPException(
            status_code=400, detail="New password can not be the same as old password"
        )

    new_password_hash = bcrypt.hashpw(
        password.new_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    db_user = db.query(user_model.User).filter(user_model.User.id == user_id).first()
    if not bcrypt.checkpw(
        current_password.encode("utf-8"), db_user.hashed_password.encode("utf-8")
    ):
        raise HTTPException(status_code=400, detail="Incorrect password")

    return await user_crud.update_user_password(db, db_user, new_password_hash)


@router.patch(
    "/{user_id}/",
    response_model=user_schema.UserUpdate,
    dependencies=[Depends(get_current_admin_user)],
)
async def update_user(
    user_id: UUID4,
    user: user_schema.UserUpdate,
    db: Session = Depends(get_db),
):
    return await user_crud.update_user(db, user_id=user_id, user=user)


@router.delete(
    "/{user_id}/", status_code=204, dependencies=[Depends(get_current_admin_user)]
)
async def delete_user(
    user_id: UUID4,
    db: Session = Depends(get_db),
):
    return await user_crud.delete_user(db, user_id=user_id)
