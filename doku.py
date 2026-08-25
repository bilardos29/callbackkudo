import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import uuid
from fastapi import FastAPI, HTTPException, Request
import requests

app = FastAPI(title="DOKU VA Top-up & Callback")

# --- KONFIGURASI DOKU SANDBOX ---
DOKU_CLIENT_ID = "BRN-0230-1787648365302"
DOKU_SECRET_KEY = "SK-4bNXUPeLYtiIDoVFrcPT"
DOKU_BASE_URL = "https://api-sandbox.doku.com"

# In-memory storage (Hanya untuk local/single-process debugging)
va_storage = {}


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def generate_digest(json_body_str: str) -> str:
    """Membuat SHA-256 Digest dari payload body."""
    hash_object = hashlib.sha256(json_body_str.encode("utf-8"))
    return base64.b64encode(hash_object.digest()).decode("utf-8")


def generate_signature(
    client_id: str,
    secret_key: str,
    request_id: str,
    timestamp: str,
    target_path: str,
    digest: str = None,
) -> str:
    """Membuat HMAC-SHA256 Signature sesuai spesifikasi Jokul/DOKU."""
    component = (
        f"Client-Id:{client_id}\n"
        f"Request-Id:{request_id}\n"
        f"Request-Timestamp:{timestamp}\n"
        f"Request-Target:{target_path}"
    )
    if digest:
        component += f"\nDigest:{digest}"

    signature_bytes = hmac.new(
        secret_key.encode("utf-8"),
        component.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"HMACSHA256={base64.b64encode(signature_bytes).decode('utf-8')}"


def verify_signature(
    client_id: str,
    secret_key: str,
    request_id: str,
    timestamp: str,
    target_path: str,
    provided_signature: str,
    digest: str = None,
) -> bool:
    expected_signature = generate_signature(
        client_id, secret_key, request_id, timestamp, target_path, digest
    )
    return hmac.compare_digest(expected_signature, provided_signature)


# ==========================================
# 1. API CREATE VIRTUAL ACCOUNT
# ==========================================
@app.post("/api/topup/create-va")
def create_virtual_account(amount: int, order_id: str = None):
    if not order_id:
        order_id = f"TOPUP-{uuid.uuid4().hex[:8].upper()}"

    target_path = "/bca-virtual-account/v2/payment-code"
    request_url = f"{DOKU_BASE_URL}{target_path}"

    request_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "order": {
            "invoice_number": order_id,
            "amount": amount,
        },
        "virtual_account_info": {
            "expired_time": 60,
            "reusable_status": False,
            "info1": "Topup Balance",
        },
        "customer": {
            "name": "User Topup",
            "email": "user@example.com",
        },
    }

    body_str = json.dumps(payload, separators=(",", ":"))
    digest = generate_digest(body_str)
    signature = generate_signature(
        DOKU_CLIENT_ID,
        DOKU_SECRET_KEY,
        request_id,
        timestamp,
        target_path,
        digest,
    )

    headers = {
        "Client-Id": DOKU_CLIENT_ID,
        "Request-Id": request_id,
        "Request-Timestamp": timestamp,
        "Signature": signature,
        "Content-Type": "application/json",
        "Digest": digest,
    }

    response = requests.post(request_url, headers=headers, data=body_str)

    if response.status_code in [200, 201]:
        result = response.json()
        va_number = result.get("virtual_account_info", {}).get("virtual_account_number")
        if va_number:
            va_storage[va_number] = {
                "invoice_number": order_id,
                "amount": amount,
                "status": "PENDING",
            }
        return result
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)


# ==========================================
# 2. API CALLBACK UNIFIED (INQUIRY & PAYMENT)
# ==========================================
@app.post("/api/doku/callback")
async def doku_callback(request: Request):
    # Ambil headers secara case-insensitive
    headers = {k.lower(): v for k, v in request.headers.items()}
    client_id = headers.get("client-id")
    request_id = headers.get("request-id")
    request_timestamp = headers.get("request-timestamp")
    signature = headers.get("signature")
    digest = headers.get("digest")

    body_raw = await request.body()
    body_str = body_raw.decode("utf-8") if body_raw else "{}"

    print("\n" + "=" * 60)
    print(">>> [DOKU CALLBACK MASUK] <<<")
    print(f"Path: {request.url.path}")
    print(f"Client-Id: {client_id}")
    print(f"Request-Id: {request_id}")
    print(f"Timestamp: {request_timestamp}")
    print(f"Signature: {signature}")
    print(f"Digest: {digest}")
    print(f"Body: {body_str}")
    print("=" * 60 + "\n")

    if not all([client_id, request_id, request_timestamp, signature, digest]):
        print("❌ Error: Missing required headers")
        raise HTTPException(status_code=400, detail="Missing required headers")

    try:
        data = json.loads(body_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

    # 1. Validasi Digest
    calculated_digest = generate_digest(body_str)
    if digest != calculated_digest:
        print(f"❌ Digest Mismatch! Got: {digest}, Expected: {calculated_digest}")
        raise HTTPException(status_code=401, detail="Digest mismatch")

    # 2. Validasi Signature
    target_path = request.url.path  # Menggunakan path dinamis (/api/doku/callback)
    if not verify_signature(
        client_id,
        DOKU_SECRET_KEY,
        request_id,
        request_timestamp,
        target_path,
        signature,
        digest,
    ):
        print("❌ Signature Mismatch!")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 3. Parsing Data
    order_info = data.get("order", {})
    invoice_number = order_info.get("invoice_number", "")
    amount = order_info.get("amount", 0)

    va_info = data.get("virtual_account_info", {})
    va_number = va_info.get("virtual_account_number", "")

    inquiry_info = data.get("virtual_account_inquiry")
    transaction_info = data.get("transaction", {})
    trx_status = transaction_info.get("status")

    # CASE 1: INQUIRY REQUEST
    if inquiry_info and not trx_status:
        print(f"📋 [INQUIRY] VA: {va_number}, Invoice: {invoice_number}")
        return {
            "order": {
                "invoice_number": invoice_number,
                "amount": amount,
            },
            "virtual_account_info": {
                "virtual_account_number": va_number,
                "billing_type": "FIXED_BILL",
                "info1": "Topup Balance",
            },
            "virtual_account_inquiry": {
                "status": "success",
            },
        }

    # CASE 2: PAYMENT NOTIFICATION
    elif trx_status:
        print(f"💳 [PAYMENT SUCCESS] VA: {va_number}, Status: {trx_status}, Amount: {amount}")
        return {
            "order": {
                "invoice_number": invoice_number,
                "amount": amount,
            },
            "virtual_account_info": {
                "virtual_account_number": va_number,
            },
        }

    return {"status": "OK"}


@app.get("/health")
def health():
    return {"status": "ok"}
