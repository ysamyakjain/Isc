from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
import logging
import bcrypt

from utils.db import Database

logging.basicConfig(level=logging.INFO)

ACCESS_TOKEN_EXPIRE_MINUTES = 7 * 24 * 60  # 7 days


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Function to create JWT token
def create_jwt_token(data: dict):
    to_encode = data.copy()
    expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expires})
    encoded_jwt = jwt.encode(to_encode, "xxxx1234", algorithm="HS256")
    return encoded_jwt

# Function to decode JWT token
def decode_jwt_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Error in validating Tokens",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token,"xxxx1234", algorithms=["HS256"])
        expiration_time = datetime.utcfromtimestamp(payload["exp"])
        if expiration_time < datetime.utcnow():
            # Token has expired
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception

# Dependency to get current user from JWT token
def get_current_user(token: str = Depends(oauth2_scheme)):
    decoded_payload = decode_jwt_token(token)
    return decoded_payload

# Dependency to get admin user from JWT token
def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in  ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="You are not authorized to perform this action")
    return current_user


async def hash_key(password):
    logging.info("hashing password")
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    hashed_password = hashed_password.decode("utf-8")
    logging.info("password hashed successfully")
    return hashed_password


