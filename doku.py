import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


app = FastAPI(title="DOKU VA Top-up & Callback")


# ============================================================
# CONFIGURATION
# ============================================================

DOKU_CLIENT_ID = os.getenv(
    "DOKU_CLIENT_ID",
    "BRN-0230-1787648365302",
)

DOKU_SECRET_KEY = os.getenv(
    "DOKU_SECRET_KEY",
    "SK-4bNXUPeLYtiIDoVFrcPT",
)

DOKU_BASE_URL = os.getenv(
    "DOKU_BASE_URL",
    "https://api-sandbox.doku.com",
)

# RSA PRIVATE KEY untuk Get Token B2B
#
# Di Vercel:
# DOKU_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
#
DOKU_PRIVATE_KEY = os.getenv(
    "DOKU_PRIVATE_KEY",
    "MIIE6jAcBgoqhkiG9w0BDAEDMA4ECJU6QHBcjTNKAgIIAASCBMjmdaogncYIUplXusKQNyAIUHYXeHMvP083/dtA9yArjNcZu2hxSNU+03ZU8iAgMuKjxLmB4G8zgDFncdzXdZD2iV6XCRWrE8zG7CRc3pIP6m3dOc9R/ZtSYawRB+WS1VSi08Ep8QLXLG0ytNXzCGMDKD0wknjvY2TUjppn+tYiha6ICAt1+j8h6nwF6owhUzXQMbEPTZDHc6GosFOKL1JKUupXUOEcMco3zAmnyPew2zm8kZZuGN15iBUqwZoGC8qtgKsqaTRQdYbL9epaZHPTXY0zLkkVgPEirbvpr3lnEowrb8dOo0XUe+i0/zybN3GhwcsLVj01URMhkFDi7gmJ0zdtHn6kp+NU+SgPbHYD3OXHMSwy15mISfhE2CNmynYV+sg4svzrrtTlILd9wkI2HnQlM8fRlfLy7Ze8t8d0lq6WTWtN/ewJ4MmvoeQP33zn035jFfXbeOi3ibTed6DCBboETuMe1NMYF1MQ2/9vaV4es7WqUef36G5oqADMBnGQwHvplIylwy549JoUdFVqxM5n20GkmT5ujQF0s658ZBx10jUt7zmKvUVk5MqMKmGGe+CRABm/5c+AL8+940qoxWzjmf4klZvPMUlfoQk/NCSf8WA2Tt/7rvYs9zMz25CjrhjqvbGAKs9fR3crYrvIIYyD/Gxydvvzrw52dYFS1iWfjNtm1jE6MpmaLFzVwou3ps4BlUHOohbcVq5rZO8mSj9DxTuJ7JrSi4JEXrJgEteDWKXt+0Benq6QB9WihDVsUCt1KNPTyGC5uSrL4HdQ1Jd7yEQ8Cc60qBPBQfSqh7v5vnjezE7aBeGe4OtjBfZFEwhmAu1oVzxRZTjhIIOnwRpvN0DPWp+HxbBGhIAHxpiflmhC/NtZ5DzuuFp+vc77s/1slgwd+IrHRUBVacSjbVqrwADp4MAGxaZaOZJhMKb4vF5J1XC+AirXuIeBMIzkEHhOj+8oyCGwtBVYjCG5n3q7DIvM6N3w2emT/focfVwjIw2eLe1SUl4pxbPC0ZAJjl0zr+V0MiVwWT7wCeWTT+yPe1v+pdz1k3yjn5ZGJih6PhBC1uxrAqDqrsMSo9aUOl15EFPnmkREk+Ry7pqkWvwFUuz8MkMFZcjumHMoAO9tm2z7CgF9mtAtiqgtSESOANQdlXBiZYUHMrforlSOibcaZDON0hKWj0aG7ar/d3Bm5TJqlym+zNKcrtUwAG6Av2d9nYF3mqnVa3EN6/webZ9IClbL578BljeqOE7BrfS48QIqzMYV5xpHutXX1yhxpC+khCzVa0kMMsh8MUlSJCdVKDN1Etsezz2xFrJT5psyZh08oBkwK3soVTNNMo3QJqJOw5tl7HzTMAKkIRnqBfuBqdBLDS0Fr8bNI6X0KoKee/W85+7v48hDC0DDLxJ0wvkHI2e/095HER+yi2U81oAgXuF0FFh9sxMujdAdnfE5UC2WxxRyUUpwYg/Wegy5FOUfUm38Gj6c8dR1CnYlvOhRhVEww6b4BN/kMBaAIvcj0pGdtQbfFFr1J5yzsBiFYPe1ORn8ad4KvpqfUXLLwehHpCTAWtJP61zbynK4RqaBRMkzTXvtqiscYXU1X9bTkMF+uyLrsHdl5aILITglnBoRKgh8SZs=",
)


# ============================================================
# IN-MEMORY STORAGE
# ============================================================

# Hanya untuk local/single-process debugging.
# Jangan digunakan sebagai database production.
va_storage = {}


# ============================================================
# GENERAL HELPERS
# ============================================================

def generate_digest(json_body_str: str) -> str:
    """
    SHA-256 Digest + Base64.

    Digunakan untuk API DOKU yang menggunakan
    Digest pada header.
    """
    hash_object = hashlib.sha256(
        json_body_str.encode("utf-8")
    )

    return base64.b64encode(
        hash_object.digest()
    ).decode("utf-8")


def generate_signature(
    client_id: str,
    secret_key: str,
    request_id: str,
    timestamp: str,
    target_path: str,
    digest: str = None,
) -> str:
    """
    HMAC-SHA256 signature.

    Ini digunakan oleh endpoint lama/non-SNAP
    yang sekarang sudah kamu gunakan untuk Create VA.
    """

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

    return (
        "HMACSHA256="
        + base64.b64encode(signature_bytes).decode("utf-8")
    )


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
        client_id,
        secret_key,
        request_id,
        timestamp,
        target_path,
        digest,
    )

    return hmac.compare_digest(
        expected_signature,
        provided_signature,
    )


# ============================================================
# DOKU SNAP GET TOKEN B2B
# ============================================================

def load_private_key():
    """
    Load RSA private key dari environment variable.

    Mendukung:
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

    maupun format yang memiliki escaped newline:
    \\n
    """

    if not DOKU_PRIVATE_KEY:
        raise RuntimeError(
            "DOKU_PRIVATE_KEY belum dikonfigurasi"
        )

    private_key_string = DOKU_PRIVATE_KEY.replace(
        "\\n",
        "\n",
    )

    return serialization.load_pem_private_key(
        private_key_string.encode("utf-8"),
        password=None,
    )


def generate_doku_b2b_signature(
    client_id: str,
    timestamp: str,
) -> str:
    """
    Generate X-SIGNATURE untuk Get Token B2B.

    DOKU:
        stringToSign = client_ID + "|" + X-TIMESTAMP

    Signature:
        SHA256withRSA(privateKey, stringToSign)
    """

    private_key = load_private_key()

    string_to_sign = (
        f"{client_id}|{timestamp}"
    )

    signature = private_key.sign(
        string_to_sign.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode("utf-8")


# ============================================================
# TOKEN URL
# ============================================================

@app.post("/api/doku/token")
async def doku_token(request: Request):
    """
    TOKEN URL UNTUK DOKU.

    URL yang dimasukkan ke DOKU Dashboard:

        https://<domain-kamu>/api/doku/token

    Flow:

        DOKU
          |
          | POST /api/doku/token
          |
          v
        Merchant
          |
          | return access token
          v
        DOKU
    """

    print("\n" + "=" * 70)
    print(">>> [DOKU GET TOKEN REQUEST] <<<")
    print(f"Path: {request.url.path}")
    print(f"Method: {request.method}")

    try:

        # ----------------------------------------------------
        # 1. READ REQUEST
        # ----------------------------------------------------

        body_raw = await request.body()

        body_str = (
            body_raw.decode("utf-8")
            if body_raw
            else "{}"
        )

        headers = {
            key.lower(): value
            for key, value in request.headers.items()
        }

        x_client_key = headers.get(
            "x-client-key"
        )

        x_timestamp = headers.get(
            "x-timestamp"
        )

        x_signature = headers.get(
            "x-signature"
        )

        print(
            f"X-CLIENT-KEY : {x_client_key}"
        )

        print(
            f"X-TIMESTAMP  : {x_timestamp}"
        )

        print(
            f"X-SIGNATURE  : {x_signature}"
        )

        print(
            f"BODY         : {body_str}"
        )

        # ----------------------------------------------------
        # 2. VALIDATE HEADER
        # ----------------------------------------------------

        if not x_client_key:
            raise HTTPException(
                status_code=400,
                detail="Missing X-CLIENT-KEY",
            )

        if not x_timestamp:
            raise HTTPException(
                status_code=400,
                detail="Missing X-TIMESTAMP",
            )

        if not x_signature:
            raise HTTPException(
                status_code=400,
                detail="Missing X-SIGNATURE",
            )

        # ----------------------------------------------------
        # 3. VALIDATE CLIENT ID
        # ----------------------------------------------------

        if x_client_key != DOKU_CLIENT_ID:

            print(
                "❌ Invalid X-CLIENT-KEY"
            )

            return JSONResponse(
                status_code=401,
                content={
                    "responseCode": "4017300",
                    "responseMessage": "Unauthorized. Unknown Client",
                },
            )

        # ----------------------------------------------------
        # 4. PARSE BODY
        # ----------------------------------------------------

        try:
            data = json.loads(body_str)
        except json.JSONDecodeError:

            return JSONResponse(
                status_code=400,
                content={
                    "responseCode": "4007300",
                    "responseMessage": "Invalid JSON",
                },
            )

        grant_type = data.get(
            "grantType"
        )

        if grant_type != "client_credentials":

            return JSONResponse(
                status_code=400,
                content={
                    "responseCode": "4007300",
                    "responseMessage": (
                        "grantType must be "
                        "client_credentials"
                    ),
                },
            )

        # ----------------------------------------------------
        # 5. VERIFY DOKU SIGNATURE
        # ----------------------------------------------------

        try:

            expected_signature = (
                generate_doku_b2b_signature(
                    x_client_key,
                    x_timestamp,
                )
            )

        except Exception as e:

            print(
                f"❌ Private key error: {str(e)}"
            )

            return JSONResponse(
                status_code=500,
                content={
                    "responseCode": "5007300",
                    "responseMessage": (
                        "Private key configuration error"
                    ),
                },
            )

        if not hmac.compare_digest(
            expected_signature,
            x_signature,
        ):

            print(
                "❌ DOKU signature mismatch"
            )

            print(
                f"Expected: {expected_signature}"
            )

            return JSONResponse(
                status_code=401,
                content={
                    "responseCode": "4017300",
                    "responseMessage": (
                        "Unauthorized. Signature"
                    ),
                },
            )

        print(
            "✅ DOKU signature valid"
        )

        # ----------------------------------------------------
        # 6. REQUEST TOKEN FROM DOKU
        # ----------------------------------------------------

        doku_timestamp = (
            datetime.now(timezone.utc)
            .strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        )

        doku_signature = (
            generate_doku_b2b_signature(
                DOKU_CLIENT_ID,
                doku_timestamp,
            )
        )

        token_url = (
            f"{DOKU_BASE_URL}"
            "/authorization/v1/access-token/b2b"
        )

        token_body = {
            "grantType": "client_credentials"
        }

        token_body_str = json.dumps(
            token_body,
            separators=(",", ":"),
        )

        token_headers = {
            "X-CLIENT-KEY": DOKU_CLIENT_ID,
            "X-TIMESTAMP": doku_timestamp,
            "X-SIGNATURE": doku_signature,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        print(
            "➡️ Requesting token from DOKU..."
        )

        token_response = requests.post(
            token_url,
            headers=token_headers,
            data=token_body_str,
            timeout=15,
        )

        print(
            f"DOKU TOKEN STATUS: "
            f"{token_response.status_code}"
        )

        print(
            f"DOKU TOKEN BODY: "
            f"{token_response.text}"
        )

        # ----------------------------------------------------
        # 7. HANDLE DOKU RESPONSE
        # ----------------------------------------------------

        if token_response.status_code != 200:

            return JSONResponse(
                status_code=502,
                content={
                    "responseCode": "5027300",
                    "responseMessage": (
                        "Failed to obtain token from DOKU"
                    ),
                    "dokuResponse": (
                        token_response.text
                    ),
                },
            )

        token_result = (
            token_response.json()
        )

        access_token = token_result.get(
            "accessToken"
        )

        if not access_token:

            return JSONResponse(
                status_code=502,
                content={
                    "responseCode": "5027300",
                    "responseMessage": (
                        "DOKU did not return accessToken"
                    ),
                },
            )

        # ----------------------------------------------------
        # 8. RETURN TOKEN TO DOKU
        # ----------------------------------------------------

        print(
            "✅ Access token obtained"
        )

        print(
            "✅ Returning token to DOKU"
        )

        return {
            "responseCode": token_result.get(
                "responseCode",
                "2007300",
            ),
            "responseMessage": token_result.get(
                "responseMessage",
                "Successful",
            ),
            "accessToken": access_token,
            "tokenType": token_result.get(
                "tokenType",
                "Bearer",
            ),
            "expiresIn": token_result.get(
                "expiresIn",
                "900",
            ),
            "additionalInfo": token_result.get(
                "additionalInfo",
                "",
            ),
        }

    except HTTPException:
        raise

    except Exception as e:

        print(
            f"❌ TOKEN ERROR: {str(e)}"
        )

        return JSONResponse(
            status_code=500,
            content={
                "responseCode": "5007300",
                "responseMessage": (
                    "Internal server error"
                ),
            },
        )


# ============================================================
# CREATE VIRTUAL ACCOUNT
# ============================================================

@app.post("/api/topup/create-va")
def create_virtual_account(
    amount: int,
    order_id: str = None,
):

    if not DOKU_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="DOKU_SECRET_KEY belum dikonfigurasi",
        )

    if not order_id:
        order_id = (
            f"TOPUP-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

    target_path = (
        "/bca-virtual-account/v2/payment-code"
    )

    request_url = (
        f"{DOKU_BASE_URL}"
        f"{target_path}"
    )

    request_id = str(
        uuid.uuid4()
    )

    timestamp = (
        datetime.now(timezone.utc)
        .strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )

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

    body_str = json.dumps(
        payload,
        separators=(",", ":"),
    )

    digest = generate_digest(
        body_str
    )

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
    print(">>> [CREATE DOKU VA] <<<")
    print(f"URL: {request_url}")
    print(f"Invoice: {order_id}")
    print(f"Amount: {amount}")
    print("=" * 60)

    response = requests.post(
        request_url,
        headers=headers,
        data=body_str,
        timeout=15,
    )

    if response.status_code in [200, 201]:

        result = response.json()

        va_number = (
            result
            .get("virtual_account_info", {})
            .get("virtual_account_number")
        )

        if va_number:

            va_storage[va_number] = {
                "invoice_number": order_id,
                "amount": amount,
                "status": "PENDING",
            }

        return result

    raise HTTPException(
        status_code=response.status_code,
        detail=response.text,
    )


# ============================================================
# DOKU CALLBACK / NOTIFICATION
# ============================================================

@app.post("/api/doku/callback")
async def doku_callback(
    request: Request,
):

    headers = {
        key.lower(): value
        for key, value in request.headers.items()
    }

    client_id = headers.get(
        "client-id"
    )

    request_id = headers.get(
        "request-id"
    )

    request_timestamp = headers.get(
        "request-timestamp"
    )

    signature = headers.get(
        "signature"
    )

    digest = headers.get(
        "digest"
    )

    body_raw = await request.body()

    body_str = (
        body_raw.decode("utf-8")
        if body_raw
        else "{}"
    )

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

    if not all([
        client_id,
        request_id,
        request_timestamp,
        signature,
        digest,
    ]):

        print(
            "❌ Missing required headers"
        )

        raise HTTPException(
            status_code=400,
            detail="Missing required headers",
        )

    try:

        data = json.loads(
            body_str
        )

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid JSON: {str(e)}"
            ),
        )

    # --------------------------------------------------------
    # VALIDATE DIGEST
    # --------------------------------------------------------

    calculated_digest = (
        generate_digest(body_str)
    )

    if digest != calculated_digest:

        print(
            "❌ Digest Mismatch!"
        )

        raise HTTPException(
            status_code=401,
            detail="Digest mismatch",
        )

    # --------------------------------------------------------
    # VALIDATE SIGNATURE
    # --------------------------------------------------------

    target_path = request.url.path

    if not verify_signature(
        client_id,
        DOKU_SECRET_KEY,
        request_id,
        request_timestamp,
        target_path,
        signature,
        digest,
    ):

        print(
            "❌ Signature Mismatch!"
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid signature",
        )

    # --------------------------------------------------------
    # PARSE DATA
    # --------------------------------------------------------

    order_info = data.get(
        "order",
        {},
    )

    invoice_number = (
        order_info.get(
            "invoice_number",
            "",
        )
    )

    amount = order_info.get(
        "amount",
        0,
    )

    va_info = data.get(
        "virtual_account_info",
        {},
    )

    va_number = (
        va_info.get(
            "virtual_account_number",
            "",
        )
    )

    inquiry_info = data.get(
        "virtual_account_inquiry"
    )

    transaction_info = data.get(
        "transaction",
        {},
    )

    trx_status = transaction_info.get(
        "status"
    )

    # --------------------------------------------------------
    # INQUIRY
    # --------------------------------------------------------

    if inquiry_info and not trx_status:

        print(
            f"📋 [INQUIRY] "
            f"VA: {va_number}, "
            f"Invoice: {invoice_number}"
        )

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

    # --------------------------------------------------------
    # PAYMENT
    # --------------------------------------------------------

    if trx_status:

        print(
            f"💳 [PAYMENT] "
            f"VA: {va_number}, "
            f"Status: {trx_status}, "
            f"Amount: {amount}"
        )

        return {
            "order": {
                "invoice_number": invoice_number,
                "amount": amount,
            },
            "virtual_account_info": {
                "virtual_account_number": va_number,
            },
        }

    return {
        "status": "OK"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok"
    }
