import textwrap

import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-6cjm2yk0.apps.exam.local"

# The public key body from the assignment (one line, no header/footer).
KEY_BODY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuYcxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMIDEkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXcWyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfWed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfISI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIXdQIDAQAB"
)

# Rebuild a proper PEM file: header, 64-character lines, footer.
PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    + "\n".join(textwrap.wrap(KEY_BODY, 64))
    + "\n-----END PUBLIC KEY-----\n"
)

app = FastAPI()


def invalid():
    return JSONResponse(status_code=401, content={"valid": False})


@app.get("/")
def home():
    return {"status": "ok", "use": "POST /verify"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token")
        if not isinstance(token, str) or not token:
            return invalid()

        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],      # only RS256 is accepted
            audience=AUDIENCE,         # checks aud
            issuer=ISSUER,             # checks iss
            options={"require": ["exp", "iss", "aud"]},  # checks exp
        )
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }
    except Exception:
        # bad signature, expired, wrong aud/iss, malformed token, bad JSON...
        return invalid()