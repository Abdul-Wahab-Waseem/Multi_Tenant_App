from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select,col

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============================= SQL & DB Config ============================
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

app = FastAPI(lifespan=lifespan)

# ============================== Data Models ============================
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
    tenants: List["Tenant"] = Relationship(back_populates="users", link_model=TenantUserLink)

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int

class TenantBase(SQLModel):
    name: str = Field(unique=True, index=True)

class Tenant(TenantBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    users: List[User] = Relationship(back_populates="tenants", link_model=TenantUserLink)

class TenantCreate(TenantBase):
    pass

class TenantRead(TenantBase):
    id: int
    role: UserRole

class AddMemberRequest(SQLModel):
    email: EmailStr
    role: UserRole = UserRole.MEMBER

class ItemOrderLink(SQLModel, table=True):
    item_id: int = Field(foreign_key="item.id", primary_key=True)
    order_id: int = Field(foreign_key="order.id", primary_key=True)

class ItemBase(SQLModel):
    name: str
    details: Optional[str] = None
    category: str

class Item(ItemBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    orders: List["Order"] = Relationship(back_populates="items", link_model=ItemOrderLink)
    user_id: int = Field(foreign_key="user.id", index=True)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)

class ItemCreate(ItemBase):
    pass

class ItemRead(ItemBase):
    id: int
    tenant_id: int
    user_id: int

class ItemUpdate(SQLModel):
    name: Optional[str] = None
    details: Optional[str] = None
    category: Optional[str] = None

class OrderBase(SQLModel):
    order_date: date = Field(default_factory=date.today)

class Order(OrderBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    items: List[Item] = Relationship(back_populates="orders", link_model=ItemOrderLink)
    tenant_id: int = Field(foreign_key="tenant.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)

class OrderCreate(SQLModel):
    item_ids: List[int]

class OrderRead(OrderBase):
    id: int
    user_id: int
    tenant_id: int

# ================================= Auth Config =================================
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
        raise HTTPException(status_code=400, detail="Invalid email or password")
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
    existing_tenant = session.exec(select(Tenant).where(Tenant.name == tenant_data.name)).first()
    if existing_tenant:
        raise HTTPException(status_code=400, detail="Corporation name already registered")

    tenant = Tenant(name=tenant_data.name)
    session.add(tenant)
    session.commit()
    session.refresh(tenant)

    link = TenantUserLink(tenant_id=tenant.id, user_id=current_user.id, role=UserRole.ADMIN)
    session.add(link)
    session.commit()

    return TenantRead(id=tenant.id, name=tenant.name, role=UserRole.ADMIN)

@app.post("/tenants/{tenant_id}/item", response_model=ItemRead, tags=["Tenant Items"])
def create_item(
    tenant_id: int,
    item_data: ItemCreate,
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
        raise HTTPException(status_code=403, detail="Only Tenant Admins can add items")

    db_item = Item(
        **item_data.model_dump(),
        user_id=current_user.id,
        tenant_id=tenant_id
    )
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item

@app.get("/Dashboard/Items",response_model=List[ItemRead],tags=["Dashboard"])
def dashboard(
    session: Session = Depends(get_session)
):
    items = session.exec(select(Item)).all()
    if not items:
        raise HTTPException(
            status_code= 400,
            detail="No items Exist"
        )
    return items

@app.patch(
        "/Tenant/{tenant_id}/Items/{item_id}",
        response_model=ItemRead,
        tags=["Tenant Items"])
def update_item(
    item_data: ItemUpdate,
    current_user: Annotated[User,Depends(verify_token)],
    tenant_id: int,
    item_id: int,
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
        raise HTTPException(status_code=403, detail="Only Tenant Admins can add items")
    statement = select(Item).where(item_id == Item.id, Item.tenant_id == tenant_id)
    item = session.exec(statement).first()
    if not item:
        raise HTTPException(
            status_code=403,
            detail="There is no such an item exists"
        )
    updated_item = item_data.model_dump(exclude_unset=True)
    item.sqlmodel_update(updated_item)

    session.add(item)
    session.commit()
    session.refresh(item)

    return item

@app.delete(
        "/Tenant/{tenant_id}/Items/{item_id}",
        status_code=status.HTTP_200_OK,
        tags=["Tenant Items"]
)
def del_item(
    tenant_id: int,
    item_id: int,
    current_user: Annotated[User,Depends(verify_token)],
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
        raise HTTPException(status_code=403, detail="Only Tenant Admins can Delete items")

    item = session.exec(select(Item).where(Item.id == item_id, Item.tenant_id == tenant_id)).first()
    if not item:
        raise HTTPException(
            status_code=403,
            detail="There is not such item exists"
        )
    session.delete(item)
    session.commit()
    return{
        "ok": True
    }

@app.post("/Order/", response_model=OrderRead, tags=["Orders"])
def create_order(
    order_data: OrderCreate,
    current_user: Annotated[User, Depends(verify_token)],
    session: Session = Depends(get_session)
):
    if not order_data.item_ids:
        raise HTTPException(status_code=400, detail="Order must contain item IDs")

    # Fetch matching items from DB
    items = session.exec(
        select(Item).where(Item.__table__.c.id.in_(order_data.item_ids))
    ).all()
    if len(items) != len(order_data.item_ids):
        raise HTTPException(status_code=404, detail="One or more item IDs were not found")

    tenant_id = items[0].tenant_id

    db_order = Order(user_id=current_user.id, tenant_id=tenant_id)
    db_order.items = items

    session.add(db_order)
    session.commit()
    session.refresh(db_order)
    return db_order
@app.get("/Tenant/{tenant_id}/orders",response_model=List[OrderRead],tags=["Tenant Orders"])
def read_orders(
    current_user:Annotated[User,Depends(verify_token)],
    tenant_id: int,
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
        raise HTTPException(
            status_code=403,
            detail="Only Tenant Admin Can See Their Orders"
        )
    orders = session.exec(select(Order).where(Order.tenant_id == tenant_id)).all()
    return orders