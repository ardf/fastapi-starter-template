from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
import os


load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore", env_file=".env", env_file_encoding="utf-8"
    )

    DEFAULT_SUPER_ADMIN_EMAIL: str = os.environ.get("DEFAULT_SUPER_ADMIN_EMAIL")
    DEFAULT_SUPER_ADMIN_PASSWORD: str = os.environ.get("DEFAULT_SUPER_ADMIN_PASSWORD")

    APP_SECRET_KEY: str = os.environ.get("appsecretkey")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = os.environ.get(
        "ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24
    )
    REFRESH_TOKEN_EXPIRE_MINUTES: int = os.environ.get(
        "REFRESH_TOKEN_EXPIRE_MINUTES", 60 * 24 * 7
    )

    DATABASE_URL: str = os.environ.get("DATABASE_URL")


settings = Settings()
