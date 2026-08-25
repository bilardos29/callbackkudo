import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import uuid
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
import requests
from mangum import Mangum

app = FastAPI(title="DOKU VA Top-up & Callback")

# --- KONFIGURASI DOKU SANDBOX ---
DOKU_CLIENT_ID = "BRN-0230-1787648365302"
DOKU_SECRET_KEY = "SK-4bNXUPeLYtiIDoVFrcPT"
DOKU_BASE_URL = "https://api-sandbox.doku.com"

# --- STORAGE SEMENTARA (untuk production, gunakan database) ---
va_storage = {}  # Format: {va_number: {invoice_number, amount, order_id, created_at, status}}


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
    """Membuat HMAC-SHA256 Signature sesuai spesifikasi DOKU."""
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
    """Verifikasi signature dari request DOKU callback."""
    expected_signature = generate_signature(
        client_id, secret_key, request_id, timestamp, target_path, digest
    )
    return hmac.compare_digest(expected_signature, provided_signature)


# ==========================================
# 1. API UNTUK GENERATE VIRTUAL ACCOUNT
# ==========================================
@app.post("/api/topup/create-va")
def create_virtual_account(amount: int, order_id: str = None):
    """
    Create Virtual Account untuk topup.
    """
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

    print("\n" + "=" * 60)
    print(">>> [CREATE VA REQUEST KE DOKU] <<<")
    print(f"Order ID: {order_id}")
    print(f"Amount: Rp{amount}")
    print(f"Request URL: {request_url}")
    print("=" * 60 + "\n")

    response = requests.post(request_url, headers=headers, data=body_str)

    if response.status_code in [200, 201]:
        result = response.json()
        
        va_number = result.get("virtual_account_info", {}).get("virtual_account_number")
        if va_number:
            va_storage[va_number] = {
                "invoice_number": order_id,
                "amount": amount,
                "order_id": order_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "PENDING",
                "va_number": va_number,
            }
            print(f"✅ VA berhasil dibuat dan disimpan: {va_number}")
        
        return result
    else:
        print(f"❌ Error: {response.status_code} - {response.text}")
        raise HTTPException(
            status_code=response.status_code, detail=response.text
        )


# ==========================================
# 2. API CALLBACK LENGKAP (INQUIRY + PAYMENT) - FIXED VERSION
# ==========================================
@app.post("/api/doku/callback")
async def doku_callback(
    request: Request,
    client_id: str = Header(None),
    request_id: str = Header(None),
    request_timestamp: str = Header(None),
    signature: str = Header(None),
    digest: str = Header(None),
):
    """
    Endpoint unified untuk INQUIRY REQUEST dan PAYMENT NOTIFICATION.
    
    ⚠️ PENTING: Pastikan header names di DOKU dashboard sesuai (case-sensitive).
    Gunakan: Client-Id, Request-Id, Request-Timestamp, Signature, Digest
    """
    body_raw = await request.body()
    body_str = body_raw.decode("utf-8") if body_raw else "{}"

    # Debug: Print all headers yang masuk
    print("\n" + "=" * 70)
    print(">>> [DOKU CALLBACK MASUK - DETAILED DEBUG] <<<")
    print(f"All Headers: {dict(request.headers)}")
    print(f"Client-Id: {client_id}")
    print(f"Request-Id: {request_id}")
    print(f"Request-Timestamp: {request_timestamp}")
    print(f"Signature: {signature}")
    print(f"Digest (header): {digest}")
    print(f"Body: {body_str[:300]}")
    print("=" * 70 + "\n")

    # ⚠️ VALIDASI: Semua header HARUS ada
    if not all([client_id, request_id, request_timestamp, signature, digest]):
        print("❌ ERROR: Missing required headers!")
        print(f"   client_id={client_id}, request_id={request_id}, ")
        print(f"   timestamp={request_timestamp}, signature={signature}, digest={digest}")
        raise HTTPException(status_code=400, detail="Missing required headers")

    # Parse request body
    try:
        data = json.loads(body_str)
    except Exception as e:
        print(f"❌ Error parsing JSON: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # ✅ STEP 1: Verify digest dari body yang diterima
    calculated_digest = generate_digest(body_str)
    if digest != calculated_digest:
        print(f"❌ DIGEST MISMATCH!")
        print(f"   Received: {digest}")
        print(f"   Calculated: {calculated_digest}")
        raise HTTPException(status_code=401, detail="Digest verification failed")
    else:
        print(f"✅ Digest verified OK")

    # ✅ STEP 2: Verify signature
    target_path = "/api/doku/callback"
    if not verify_signature(
        client_id,
        DOKU_SECRET_KEY,
        request_id,
        request_timestamp,
        target_path,
        signature,
        digest,
    ):
        print(f"❌ SIGNATURE VERIFICATION FAILED!")
        print(f"   Provided: {signature}")
        expected_sig = generate_signature(
            client_id, DOKU_SECRET_KEY, request_id, request_timestamp, target_path, digest
        )
        print(f"   Expected: {expected_sig}")
        raise HTTPException(status_code=401, detail="Signature verification failed")
    else:
        print(f"✅ Signature verified OK")

    # Extract data dari request
    order_info = data.get("order", {})
    invoice_number = order_info.get("invoice_number", "")
    amount = order_info.get("amount")
    
    va_info = data.get("virtual_account_info", {})
    va_number = va_info.get("virtual_account_number", "")
    
    inquiry_info = data.get("virtual_account_inquiry")
    transaction_info = data.get("transaction", {})
    trx_status = transaction_info.get("status")

    # ==========================================
    # CASE 1: INQUIRY REQUEST (dari bank/acquirer)
    # ==========================================
    if inquiry_info and not trx_status:
        print(f"📋 [INQUIRY REQUEST] VA: {va_number}")
        print(f"   Invoice: {invoice_number}")
        
        va_data = va_storage.get(va_number, {})
        stored_invoice = va_data.get("invoice_number", invoice_number)
        stored_amount = va_data.get("amount", amount)
        
        inquiry_response = {
            "order": {
                "invoice_number": stored_invoice,
                "amount": stored_amount,
            },
            "virtual_account_info": {
                "virtual_account_number": va_number,
                "billing_type": "FIXED_BILL",
                "info1": "Topup Balance",
            },
            "virtual_account_inquiry": {
                "status": "success",
            },
            "customer": {
                "name": "User Topup",
                "email": "user@example.com",
            },
        }
        
        print(f"✅ Inquiry SUCCESS response dikirim")
        return inquiry_response

    # ==========================================
    # CASE 2: PAYMENT NOTIFICATION (notifikasi pembayaran)
    # ==========================================
    elif trx_status:
        print(f"💳 [PAYMENT NOTIFICATION] Status: {trx_status}")
        print(f"   Invoice: {invoice_number}")
        print(f"   Amount: Rp{amount}")
        print(f"   VA: {va_number}")
        
        if va_number in va_storage:
            va_storage[va_number]["status"] = trx_status
            print(f"   ✅ Status updated: {trx_status}")
        
        if trx_status == "SUCCESS":
            print(f"   🎉 TOPUP BERHASIL! Rp{amount} untuk Invoice: {invoice_number}")
            # TODO: Update user balance, send email, log transaction
        
        elif trx_status == "FAILED":
            print(f"   ❌ TOPUP GAGAL untuk Invoice: {invoice_number}")
        
        payment_response = {
            "order": {
                "invoice_number": invoice_number,
                "amount": amount,
            },
            "virtual_account_info": {
                "virtual_account_number": va_number,
                "info1": "Topup Balance",
            },
        }
        
        return payment_response

    # ==========================================
    # CASE 3: UNKNOWN REQUEST
    # ==========================================
    else:
        print(f"⚠️  Unknown request type")
        raise HTTPException(status_code=400, detail="Unknown request type")


# ==========================================
# 3. API UNTUK STATUS CHECK
# ==========================================
@app.get("/api/topup/status/{va_number}")
def get_va_status(va_number: str):
    """Get status VA dari storage."""
    va_data = va_storage.get(va_number)
    
    if not va_data:
        raise HTTPException(status_code=404, detail="VA not found")
    
    return {
        "va_number": va_number,
        "invoice_number": va_data.get("invoice_number"),
        "amount": va_data.get("amount"),
        "status": va_data.get("status"),
        "created_at": va_data.get("created_at"),
    }


# ==========================================
# 4. API LIST SEMUA VA
# ==========================================
@app.get("/api/topup/list")
def list_all_va():
    """List semua VA yang pernah dibuat (development only)."""
    return {
        "total": len(va_storage),
        "vas": va_storage,
    }


# ==========================================
# 5. HEALTH CHECK
# ==========================================
@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

# Handler wajib untuk Vercel serverless
handler = Mangum(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
