from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from jose import jwt, JWTError
from datetime import datetime, timedelta
from azure.cosmos import CosmosClient
import os

# === CONFIG ===
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

COSMOS_ENDPOINT = "https://prathinidhidb.documents.azure.com:443/"
COSMOS_KEY = "nrqSGo8Uj5BRispWlsy32mB1cd4Nj2c7zEHmYAp5vtOed4vZncRHMs3zcgkhxenrhaRRSoVB2PU7ACDbedAHuQ=="
DATABASE_ID = "form-database"
CONTAINER_ID = "form-container"

# === APP INITIALIZATION ===
app = FastAPI()
auth_scheme = HTTPBearer()

# === CORS SETUP ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === COSMOS DB SETUP ===
client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
database = client.create_database_if_not_exists(id=DATABASE_ID)
container = database.create_container_if_not_exists(id=CONTAINER_ID, partition_key="/mobile")

# === JWT UTILITIES ===
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# === SESSION STORE ===
session_tokens = {}

# === DEPENDENCY ===
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    user_data = verify_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    mobile = user_data.get("mobile")
    if session_tokens.get(mobile) != token:
        raise HTTPException(status_code=401, detail="Session expired or logged in elsewhere")

    return user_data

# === ROUTES ===

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    file_path = os.path.join("static", "er404.html")
    return FileResponse(file_path, status_code=404)

@app.post("/login")
async def login(data: dict):
    mobile = data.get("mobile")
    aadhaar = data.get("aadhaar")
    otp = data.get("otp")

    query = f"SELECT * FROM c WHERE c.mobile = '{mobile}' AND c.aadhaar = '{aadhaar}' AND c.otp = '{otp}'"
    users = list(container.query_items(query=query, enable_cross_partition_query=False))

    if users:
        token = create_access_token({"mobile": mobile})
        session_tokens[mobile] = token
        return {"token": token, "message": "Login successful"}

    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    mobile = user.get("mobile")

    query = f"SELECT * FROM c WHERE c.mobile = '{mobile}'"
    users = list(container.query_items(query=query, enable_cross_partition_query=False))

    if users:
        return {"user": users[0]}

    raise HTTPException(status_code=404, detail="User not found")

@app.post("/complaint")
async def file_complaint(data: dict, user=Depends(get_current_user)):
    mobile = user.get("mobile")

    complaint = {
        "id": str(datetime.utcnow().timestamp()),  # Unique ID
        "mobile": mobile,
        "applicationType": data.get("applicationType"),
        "receivedThrough": data.get("receivedThrough"),
        "problemSummary": data.get("problemSummary"),
        "religion": data.get("religion"),
        "caste": data.get("caste"),
        "occupation": data.get("occupation"),
        "timestamp": datetime.utcnow().isoformat()
    }

    container.create_item(body=complaint)
    return {"message": "Complaint filed successfully", "complaint": complaint}

# Run the application
if _name_ == "_main_":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
