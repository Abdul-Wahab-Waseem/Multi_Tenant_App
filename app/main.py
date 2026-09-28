from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, List, Optional
from pydantic import EmailStr
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select
# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============================= SQL and Table Config ============================
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

# ============================== Multi-Tenant Models ============================

class UserRole(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"

class TenantUserLink(SQLModel, table=True):
    tenant_id: int = Field(foreign_key="tenant.id", primary_key=True)
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    role: UserRole = Field(default=UserRole.MEMBER)

class UserBase(SQLModel):
    name: str
    email: EmailStr = Field(unique=True, index=True)

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str

    tenants: List["Tenant"] = Relationship(
        back_populates="users", link_model=TenantUserLink
    )

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int

class TenantBase(SQLModel):
    name: str = Field(unique=True, index=True)

class Tenant(TenantBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    users: List[User] = Relationship(
        back_populates="tenants", link_model=TenantUserLink
    )

class TenantCreate(TenantBase):
    pass

class TenantRead(TenantBase):
    id: int
    role: UserRole

class AddMemberRequest(SQLModel):
    email: EmailStr
    role: UserRole = UserRole.MEMBER

# ===================================== JWT & OAuth Config =================================
app = FastAPI(lifespan=lifespan)

SECRET_KEY = "mysecret"
ALGORITHM = "HS256"
OAuth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(
    token: Annotated[str, Depends(OAuth2_scheme)],
    session: Session = Depends(get_session),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise credentials_exception
    return user

# ===================================== Endpoints =================================

@app.post("/signup", response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def signup(user_data: UserCreate, session: Session = Depends(get_session)):
    existing_user = session.exec(select(User).where(User.email == user_data.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already registered")

    db_user = User(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.post("/login", tags=["Auth"])
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Session = Depends(get_session),
):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password",
        )
    access_token = create_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=UserRead, tags=["User"])
def get_me(current_user: Annotated[User, Depends(verify_token)]):
    return current_user

@app.post("/tenants/register", response_model=TenantRead, status_code=status.HTTP_201_CREATED, tags=["Tenant Management"])
def register_tenant(
    tenant_data: TenantCreate,
    current_user: Annotated[User, Depends(verify_token)], 
    session: Session = Depends(get_session),
):
    statement = Tenant.name == tenant_data.name
    existing_tenant = session.exec(select(Tenant).where(statement)).first()
    if existing_tenant:
        raise HTTPException(status_code=400, detail="Corporation name already registered")

    tenant = Tenant(name=tenant_data.name)
    session.add(tenant)
    session.commit()
    session.refresh(tenant)

    link = TenantUserLink(
        tenant_id=tenant.id,
        user_id=current_user.id,
        role=UserRole.ADMIN
    )
    session.add(link)
    session.commit()

    return TenantRead(id=tenant.id, name=tenant.name, role=UserRole.ADMIN)

@app.get("/users/me/tenants", response_model=List[TenantRead], tags=["User Workspace"])
def get_my_tenants(
    current_user: Annotated[User, Depends(verify_token)],
    session: Session = Depends(get_session)
):
    links = session.exec(select(TenantUserLink).where(TenantUserLink.user_id == current_user.id)).all()
    
    result = []
    for link in links:
        tenant = session.get(Tenant, link.tenant_id)
        result.append(TenantRead(id=tenant.id, name=tenant.name, role=link.role))
    return result

@app.post("/tenants/{tenant_id}/members", tags=["Tenant Admin Actions"])
def add_member_to_tenant(
    tenant_id: int,
    payload: AddMemberRequest,
    current_user: Annotated[User, Depends(verify_token)],
    session: Session = Depends(get_session)
):
    admin_link = session.exec(
        select(TenantUserLink).where(
            TenantUserLink.tenant_id == tenant_id,
            TenantUserLink.user_id == current_user.id,
            TenantUserLink.role == UserRole.ADMIN
        )
    ).first()
    if not admin_link:
        raise HTTPException(status_code=403, detail="Only Tenant Admins can add members to this workspace")

    target_user = session.exec(select(User).where(User.email == payload.email)).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User with this email does not exist")

    existing_link = session.exec(
        select(TenantUserLink).where(
            TenantUserLink.tenant_id == tenant_id,
            TenantUserLink.user_id == target_user.id
        )
    ).first()
    if existing_link:
        raise HTTPException(status_code=400, detail="User is already a member of this workspace")

    new_link = TenantUserLink(
        tenant_id=tenant_id,
        user_id=target_user.id,
        role=payload.role
    )
    session.add(new_link)
    session.commit()

    return {"message": f"Successfully added {target_user.email} as {payload.role.value} to workspace."}