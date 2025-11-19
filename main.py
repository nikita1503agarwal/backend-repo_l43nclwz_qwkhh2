import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
import jwt
from bson import ObjectId

from database import db, create_document, get_documents

# ------------------------------------------------------------
# App & CORS
# ------------------------------------------------------------
app = FastAPI(title="Barkati Cloth Store API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
TOKEN_EXPIRE_MIN = 60 * 24 * 7  # 7 days

security = HTTPBearer()


def oid(obj_id: str) -> ObjectId:
    try:
        return ObjectId(obj_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def to_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    # Convert datetimes to iso
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def hash_password(pw: str) -> str:
    import hashlib
    return hashlib.sha256((pw + os.getenv("PW_SALT", "salt")).encode()).hexdigest()


def create_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": str(user["_id"]),
        "email": user.get("email"),
        "role": user.get("role", "user"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = creds.credentials
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user = db["user"].find_one({"_id": ObjectId(data["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if user.get("blocked"):
            raise HTTPException(status_code=403, detail="User is blocked")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ------------------------------------------------------------
# Schemas
# ------------------------------------------------------------
class Variation(BaseModel):
    color: Optional[str] = None
    size: Optional[str] = None
    stock: Optional[int] = 0


class ProductIn(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(ge=0)
    category: str
    images: List[str] = []
    colors: List[str] = []
    sizes: List[str] = []
    stock: int = 0
    featured: bool = False


class ProductOut(ProductIn):
    id: str
    created_at: Optional[str] = None


class UserRegister(BaseModel):
    name: str
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserPublic(BaseModel):
    id: str
    name: str
    email: str
    role: str = "user"


class CartItem(BaseModel):
    product_id: str
    title: str
    price: float
    quantity: int = Field(ge=1)
    color: Optional[str] = None
    size: Optional[str] = None
    image: Optional[str] = None


class CheckoutIn(BaseModel):
    name: str
    email: str
    address: str
    payment_method: str = Field("JazzCash")
    items: List[CartItem]


class OrderOut(BaseModel):
    id: str
    user_id: Optional[str] = None
    items: List[CartItem]
    total: float
    status: str
    payment_status: str
    created_at: str


class MessageIn(BaseModel):
    name: str
    email: str
    message: str


class MessageReplyIn(BaseModel):
    reply: str


class BotPromptIn(BaseModel):
    prompt: str


# ------------------------------------------------------------
# Basic routes & health
# ------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "name": "Barkati Cloth Store API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": bool(os.getenv("DATABASE_URL")),
        "database_name": os.getenv("DATABASE_NAME"),
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"Error: {e}"
    return response


# ------------------------------------------------------------
# Auth & Users
# ------------------------------------------------------------
@app.post("/auth/register")
def register(payload: UserRegister):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "password": hash_password(payload.password),
        "role": "user",
        "blocked": False,
        "created_at": datetime.now(timezone.utc),
    }
    uid = db["user"].insert_one(doc).inserted_id
    user = db["user"].find_one({"_id": uid})
    token = create_token(user)
    return {"token": token, "user": to_public(user)}


@app.post("/auth/login")
def login(payload: UserLogin):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or user.get("password") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "user": to_public(user)}


@app.get("/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return to_public(user)


@app.get("/admin/users")
def list_users(_: Dict[str, Any] = Depends(require_admin)):
    users = [to_public(u) for u in db["user"].find().sort("created_at", -1)]
    return users


@app.post("/admin/users/{user_id}/block")
def block_user(user_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["user"].update_one({"_id": oid(user_id)}, {"$set": {"blocked": True}})
    return {"ok": True}


@app.post("/admin/users/{user_id}/unblock")
def unblock_user(user_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["user"].update_one({"_id": oid(user_id)}, {"$set": {"blocked": False}})
    return {"ok": True}


# ------------------------------------------------------------
# Products
# ------------------------------------------------------------
@app.get("/products")
def get_products(category: Optional[str] = None, featured: Optional[bool] = None, q: Optional[str] = None):
    filt: Dict[str, Any] = {}
    if category:
        filt["category"] = category
    if featured is not None:
        filt["featured"] = featured
    if q:
        filt["title"] = {"$regex": q, "$options": "i"}
    items = [to_public(p) for p in db["product"].find(filt).sort("created_at", -1)]
    return items


@app.get("/products/{product_id}")
def get_product(product_id: str):
    p = db["product"].find_one({"_id": oid(product_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    return to_public(p)


@app.post("/admin/products")
def create_product(payload: ProductIn, _: Dict[str, Any] = Depends(require_admin)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc)})
    pid = db["product"].insert_one(doc).inserted_id
    return to_public(db["product"].find_one({"_id": pid}))


@app.put("/admin/products/{product_id}")
def update_product(product_id: str, payload: ProductIn, _: Dict[str, Any] = Depends(require_admin)):
    db["product"].update_one({"_id": oid(product_id)}, {"$set": payload.model_dump()})
    return to_public(db["product"].find_one({"_id": oid(product_id)}))


@app.delete("/admin/products/{product_id}")
def delete_product(product_id: str, _: Dict[str, Any] = Depends(require_admin)):
    db["product"].delete_one({"_id": oid(product_id)})
    return {"ok": True}


# ------------------------------------------------------------
# Orders
# ------------------------------------------------------------
@app.post("/orders")
def create_order(payload: CheckoutIn, user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    total = sum(i.price * i.quantity for i in payload.items)
    doc = {
        "user_id": str(user["_id"]) if user else None,
        "name": payload.name,
        "email": payload.email,
        "address": payload.address,
        "payment_method": payload.payment_method,
        "items": [i.model_dump() for i in payload.items],
        "total": round(total, 2),
        "status": "Pending",
        "payment_status": "Unpaid",
        "created_at": datetime.now(timezone.utc),
    }
    oid_ = db["order"].insert_one(doc).inserted_id
    return to_public(db["order"].find_one({"_id": oid_}))


@app.get("/orders")
def my_orders(user: Dict[str, Any] = Depends(get_current_user)):
    cur = db["order"].find({"user_id": str(user["_id"])}).sort("created_at", -1)
    return [to_public(o) for o in cur]


@app.get("/admin/orders")
def all_orders(_: Dict[str, Any] = Depends(require_admin)):
    cur = db["order"].find().sort("created_at", -1)
    return [to_public(o) for o in cur]


class OrderStatusIn(BaseModel):
    status: str
    payment_status: Optional[str] = None


@app.put("/admin/orders/{order_id}/status")
def update_order_status(order_id: str, payload: OrderStatusIn, _: Dict[str, Any] = Depends(require_admin)):
    update: Dict[str, Any] = {"status": payload.status}
    if payload.payment_status is not None:
        update["payment_status"] = payload.payment_status
    db["order"].update_one({"_id": oid(order_id)}, {"$set": update})
    return to_public(db["order"].find_one({"_id": oid(order_id)}))


# Mock JazzCash notify endpoint (simulate success/failure)
class JazzNotifyIn(BaseModel):
    order_id: str
    success: bool


@app.post("/payment/jazzcash/notify")
def jazz_notify(payload: JazzNotifyIn):
    order = db["order"].find_one({"_id": oid(payload.order_id)})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    db["order"].update_one(
        {"_id": oid(payload.order_id)},
        {"$set": {"payment_status": "Paid" if payload.success else "Failed", "status": "Packed" if payload.success else "Pending"}},
    )
    return {"ok": True}


# ------------------------------------------------------------
# Messages (Contact)
# ------------------------------------------------------------
@app.post("/messages")
def create_message(payload: MessageIn):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "replies": []})
    mid = db["message"].insert_one(doc).inserted_id
    return to_public(db["message"].find_one({"_id": mid}))


@app.get("/admin/messages")
def list_messages(_: Dict[str, Any] = Depends(require_admin)):
    return [to_public(m) for m in db["message"].find().sort("created_at", -1)]


@app.post("/admin/messages/{message_id}/reply")
def reply_message(message_id: str, payload: MessageReplyIn, admin: Dict[str, Any] = Depends(require_admin)):
    reply = {"text": payload.reply, "by": admin.get("name"), "at": datetime.now(timezone.utc)}
    db["message"].update_one({"_id": oid(message_id)}, {"$push": {"replies": reply}})
    return to_public(db["message"].find_one({"_id": oid(message_id)}))


# ------------------------------------------------------------
# Chatbot
# ------------------------------------------------------------
@app.get("/chatbot/prompt")
def get_prompt():
    doc = db["botprompt"].find_one({})
    if not doc:
        doc = {"prompt": "You are a helpful fashion assistant for Barkati Cloth Store.", "created_at": datetime.now(timezone.utc)}
        _id = db["botprompt"].insert_one(doc).inserted_id
        doc["_id"] = _id
    return to_public(doc)


@app.post("/admin/chatbot/prompt")
def set_prompt(payload: BotPromptIn, _: Dict[str, Any] = Depends(require_admin)):
    existing = db["botprompt"].find_one({})
    if existing:
        db["botprompt"].update_one({"_id": existing["_id"]}, {"$set": {"prompt": payload.prompt}})
        return to_public(db["botprompt"].find_one({"_id": existing["_id"]}))
    _id = db["botprompt"].insert_one({"prompt": payload.prompt, "created_at": datetime.now(timezone.utc)}).inserted_id
    return to_public(db["botprompt"].find_one({"_id": _id}))


class ChatIn(BaseModel):
    message: str


@app.post("/chatbot/chat")
def chatbot_chat(payload: ChatIn):
    # Very simple rule-based reply using current prompt for tone
    prompt = db["botprompt"].find_one({}) or {"prompt": "Friendly"}
    msg = payload.message.lower()
    if any(k in msg for k in ["price", "cost"]):
        answer = "Our prices vary by product. Please open a product to see live pricing."
    elif any(k in msg for k in ["delivery", "ship", "shipping"]):
        answer = "We ship nationwide. Orders are delivered within 3-5 business days."
    elif any(k in msg for k in ["return", "refund"]):
        answer = "We offer a 7-day easy return policy for unused items."
    else:
        answer = "How can I help you find the perfect outfit today?"
    return {"reply": f"{prompt.get('prompt')}: {answer}"}


# ------------------------------------------------------------
# Admin dashboard metrics
# ------------------------------------------------------------
@app.get("/admin/stats")
def admin_stats(_: Dict[str, Any] = Depends(require_admin)):
    total_sales = 0.0
    total_orders = db["order"].count_documents({})
    total_users = db["user"].count_documents({})
    total_products = db["product"].count_documents({})
    for o in db["order"].find({"payment_status": "Paid"}):
        total_sales += float(o.get("total", 0))
    return {
        "total_sales": round(total_sales, 2),
        "total_orders": total_orders,
        "total_users": total_users,
        "total_products": total_products,
    }


# ------------------------------------------------------------
# SEO friendly sitemap and robots
# ------------------------------------------------------------
@app.get("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\nSitemap: /sitemap.txt"


@app.get("/sitemap.txt")
def sitemap():
    urls = ["/", "/products", "/contact", "/profile", "/checkout"]
    return "\n".join(urls)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
