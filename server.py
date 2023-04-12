"""Python Flask WebApp Auth0 integration example
"""

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from fastapi.middleware.cors import CORSMiddleware

from dotenv import find_dotenv, load_dotenv
from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

origins = ["http://localhost:3000", "http://127.0.0.1:3000", "http://127.0.0.1:8000", "http://localhost:8000"]

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

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
@app.route("/callback", methods=["GET", "POST"])
async def callback(request):
    token = await oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    response = RedirectResponse("http://localhost:3000")
    response.set_cookie("token", token, domain="localhost", samesite='none', secure=True)
    return response

@app.route("/getcookie", methods=["GET", "POST"])
async def getcookie(request):
    print("Cookie!!")
    print(request.cookies.get("token"))
    #print(list(request.headers.keys()))
    print(request.headers)
    return RedirectResponse("http://localhost:3000")


@app.route("/login")
async def login(request):
    redirect_uri = request.url_for("callback")
    print(str(redirect_uri))
    return await oauth.auth0.authorize_redirect(
       request, str(redirect_uri)
    )


@app.route("/logout")
async def logout(request):
    request.session.clear()
    response = RedirectResponse(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": request.url_for("getcookie"),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )
    response.delete_cookie("token")
    return response


if __name__ == "__main__":
    app.run(host="localhost", port=env.get("PORT", 3000))
