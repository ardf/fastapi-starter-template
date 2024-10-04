from pydantic import BaseModel, UUID4, field_validator


class UserBase(BaseModel):
    email: str
    first_name: str
    last_name: str
    is_active: bool = True
    is_admin: bool | None = False
    is_super_admin: bool | None = False

    @field_validator("is_admin", "is_super_admin")
    def set_false_if_none(cls, v):
        return False if v is None else v


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: UUID4
    is_active: bool

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_admin: bool | None = None
    is_super_admin: bool | None = None


class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str


class UserPasswordReset(BaseModel):
    new_password: str


class UserDelete(BaseModel):
    id: UUID4
