from app.models import user as models
from app.schemas import user as schemas
from sqlalchemy.orm import Session
from pydantic import UUID4
from fastapi import HTTPException


async def get_user(db: Session, user_id: UUID4):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


async def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


async def get_users(db: Session, skip: int = 0, limit: int = 100):
    return (
        db.query(models.User)
        .order_by(models.User.first_name, models.User.last_name)
        .offset(skip)
        .limit(limit)
        .all()
    )


async def create_user(db: Session, user: schemas.UserCreate, hashed_password: bytes):
    user_data = user.model_dump(exclude={"password"})

    user_data["hashed_password"] = hashed_password

    db_user = models.User(**user_data)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


async def update_user(db: Session, user_id: UUID4, user: schemas.UserUpdate):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    update_data = user.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user


async def delete_user(db: Session, user_id: UUID4):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()


async def update_user_password(db: Session, db_user: models.User, hashed_password: str):
    db_user.hashed_password = hashed_password
    db.commit()
    db.refresh(db_user)
    return db_user
