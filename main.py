import os
import logging
import time
import bcrypt

from typing import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.crud import user as user_crud
from app.schemas import user as user_schema
from app.database import SessionLocal
from app.endpoints import user, token
from app.config import settings
from app.logger import get_logger

# Configure the logger
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create default super admin user if doesn't exist
    email = settings.DEFAULT_SUPER_ADMIN_EMAIL
    password = settings.DEFAULT_SUPER_ADMIN_PASSWORD
    db = SessionLocal()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user = await user_crud.get_user_by_email(db, email)
    if not user:
        default_super_admin = user_schema.UserCreate(
            email=email,
            password=password,
            first_name="Root",
            last_name="Admin",
            is_active=True,
            is_admin=True,
            is_super_admin=True,
        )
        user = await user_crud.create_user(
            db, default_super_admin, hashed_password.decode("utf-8")
        )
        logger.info(f"Created default super admin user: {email}")
    elif not user.is_super_admin or not user.is_admin:
        user.is_super_admin = True
        user.is_admin = True
        db.commit()
        logger.info(f"Updated default super admin user: {email}")
    else:
        logger.info(f"Default super admin user already exists: {email}")
    db.close()
    yield
    logger.info("Shutting down the application")


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def log_all_requests(request: Request, call_next: Callable):
    start_time = time.time()
    logger.info(f"Request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response: Status {response.status_code}")
    end_time = time.time()
    logger.info(f"Response took {end_time-start_time} seconds")
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5173",
    ).split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Hello World"}


app.include_router(token.router, prefix="/token", tags=["token"])
app.include_router(user.router, prefix="/users", tags=["users"])


logger.info("FastAPI application initialized")
