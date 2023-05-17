import jwt
from jwt import PyJWKClient
from starlette.responses import JSONResponse
from os import environ as env
from urllib.parse import quote_plus, urlencode
from fastapi.middleware.cors import CORSMiddleware
import time
from dotenv import find_dotenv, load_dotenv
from fastapi import FastAPI, Request, APIRouter
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

auth_router = APIRouter()

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

frontend_url = "http://" + env.get("PROXY_IP")

origins = ["http://localhost:3000", "http://127.0.0.1:3000", "http://127.0.0.1:8000", "http://localhost:8000", frontend_url]

app.add_middleware(SessionMiddleware,secret_key=env.get("APP_SECRET_KEY"))
app.add_middleware(
        CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth = OAuth()

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Controllers API
@auth_router.route("/callback", methods=["GET", "POST"])
async def callback(request):
    token = await oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    response = RedirectResponse(frontend_url)
    response.set_cookie("token", token)
    return response

@auth_router.route("/login")
async def login(request):
    redirect_uri = request.url_for("callback")
    return await oauth.auth0.authorize_redirect(
       request, str(redirect_uri)
    )

from fastapi import HTTPException

@auth_router.route("/verify", methods=["POST"])
async def verify(request):
    print("Verify json")
    try:
        body = await request.json()
        print(body)
        token_id = body["id_token"]
        if not token_id:
            raise HTTPException(status_code=400, detail="Missing id_token in request body")
        jwks_url = f'https://{env.get("AUTH0_DOMAIN")}/.well-known/jwks.json'
        
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token_id)
        print("Verify json")
        data = jwt.decode(
            token_id,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )
        
        print("data: ", data)
        
        return JSONResponse({"message": "Token verification successful"})
    
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail="Token verification failed: Invalid token") from e
    
    except jwt.InvalidSignatureError as e:
        raise HTTPException(status_code=401, detail="Signature verification failed") from e
    
    except jwt.PyJWKClientError as e:
        raise HTTPException(status_code=401, detail="Failed to parse token") from e
    except Exception as e:
        raise HTTPException(status_code=401, detail="Broken token") from e


@auth_router.route("/logout")
async def logout(request):
    request.session.clear()
    response = RedirectResponse(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": frontend_url,
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )
    response.delete_cookie("token")
    return response

app.include_router(auth_router, prefix="/auth")

if __name__ == "__main__":
    app.run(host="localhost", port=env.get("PORT", 8000))
