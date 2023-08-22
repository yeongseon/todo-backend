import os
import jwt
import json
import logging
import requests
import time
from datetime import datetime, timedelta
import azure.functions as func
from azure.cosmos import CosmosClient, PartitionKey, exceptions


def get_kakao_token(authorization_code):
    logging.info(
        f"Requesting access token with authorization code: {authorization_code}"
    )

    url = "https://kauth.kakao.com/oauth/token"

    data = {
        "grant_type": "authorization_code",
        "client_id": os.getenv("CLIENT_ID"),
        "client_secret": os.getenv("CLIENT_SECRET"),
        "redirect_uri": os.getenv("REDIRECT_URI"),
        "code": authorization_code,
    }

    response = requests.post(url, data=data)
    response.raise_for_status()

    return response.json().get("access_token")


def store_user_info_cosmosdb(user_info):
    # Initialize Cosmos Client
    url = os.getenv("COSMOS_ACCOUNT_URI")
    key = os.getenv("COSMOS_ACCOUNT_KEY")
    client = CosmosClient(url, credential=key)

    # Select database
    database_name = "todo"
    database = client.get_database_client(database_name)

    # Select container
    container_name = "users"
    container = database.get_container_client(container_name)

    # Store the user info
    # container.upsert_item(body=user_info)
    user_info['id'] = str(user_info['id'])
    container.upsert_item(body=user_info)


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    authorization_code = req.get_json().get("authorizationCode")
    logging.info(f"authorization_code: {authorization_code}")

    access_token = get_kakao_token(authorization_code)
    logging.info(f"access_token: {access_token}")

    if access_token:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
        }

        response = requests.get("https://kapi.kakao.com/v2/user/me", headers=headers)
        response.raise_for_status()  # 에러가 발생하면 예외를 발생시킵니다.

        user_info = response.json()
        logging.info(f"user_info: {user_info}")

        # Store the user info in Cosmos DB
        store_user_info_cosmosdb(user_info)

        # generate JWT token
        exp_timestamp = int(time.time()) + 60 * 60
        token = jwt.encode({**user_info, "exp": exp_timestamp}, os.getenv("JWT_SECRET_KEY"), algorithm="HS256")

        return func.HttpResponse(body=json.dumps({"token": token, "user": user_info}))


    else:
        return func.HttpResponse(
            body=json.dumps(
                {"message": "Please pass a valid kakao token in the request body"}
            ),
            status_code=400,
        )
