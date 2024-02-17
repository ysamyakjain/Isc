from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from bson import ObjectId
from datetime import datetime, timedelta
from fastapi.encoders import jsonable_encoder
import bcrypt
import datetime
import logging
from fastapi import Depends
from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
import logging
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from datetime import datetime
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
# internal imports
from models.all_models import *
from utils.auth import *


app = FastAPI()

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def main():
    return {"message": "Everything is working fine :)"}


# OAuth2PasswordBearer for JWT Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# custom error handler for validation errors coming from pydantic
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_messages = [
        {"field": error["loc"][-1], "message": error["msg"]} for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": False,
            "message": "Validation error",
            "response": error_messages,
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": False,
            "message": "HTTP exception",
            "response": str(exc.detail),
        },
    )


# USER APIS


# FastAPI route for user registration
@app.post("/user-register", tags=["User-authentication"])
async def register(user: NewUserRegistration) -> JSONResponse:
    # Connect to MongoDB
    try:
        db = Database("isc", "users")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        existing_user = existing_user = collection.find_one(
            {"$or": [{"username": user.username}, {"email": user.email}]}
        )
        if existing_user:
            logging.info(f"User with username {user.username} already exists")
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "User with this username/email already exists",
                    "response": "Try a different username and email to register",
                },
            )
        logging.info(
            f"User with username {user.username} does not exist, creating new user"
        )
        # Hash the password before saving to MongoDB
        hashed_password = await hash_key(user.password)
        # Insert user details into MongoDB
        user_data = user.dict()
        user_data["password"] = hashed_password
        user_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_data["last_updated"] = None
        user_data["role"] = "user"
        inserted_user = collection.insert_one(user_data)
        logging.info(
            f"User registered successfully with id: {inserted_user.inserted_id}"
        )
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "User registered successfully",
                "response": "Sign in to continue with our services",
            },
        )
    except Exception as e:
        logging.error(f"Error registering user: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# FastAPI route for user login
@app.post("/user-login", tags=["User-authentication"])
async def login(user_login: UserLogin) -> JSONResponse:
    try:

        # Check if email or username is provided
        if user_login.email is None and user_login.username is None:
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "email or username is required to login",
                    "response": "Provide valid email or username to login",
                },
            )
    except Exception as e:
        logging.error(f"Error logging in user: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

    try:
        db = Database("isc", "users")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Validate user credentials
        if user_login.email:
            user = collection.find_one({"email": user_login.email})
        else:
            user = collection.find_one({"username": user_login.username})
        logging.info(f"User found: {user}")
        if not user or not bcrypt.checkpw(
            user_login.password.encode("utf-8"), user["password"].encode("utf-8")
        ):
            logging.info(
                f"Invalid credentials for user: {user_login.email or user_login.username}"
            )
            return JSONResponse(
                status_code=401,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Invalid credentials",
                    "response": "Please provide valid email/username and password",
                },
            )
        # Generate JWT token
        token_data = {
            "id": str(user["_id"]),
            "email": user["email"],
            "username": user["username"],
            "role": user["role"],
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=7 * 24 * 60),
            "Last-login": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "custom_data": [],
        }
        token = create_jwt_token(token_data)
        logging.info(f"User {user['username']} logged in successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "User logged in successfully",
                "response": {"token": token},
            },
        )
    except Exception as e:
        logging.error(f"Error logging in user: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# route for updating the user-details
@app.put("/update-user", tags=["User-authentication"])
async def update_user(
    user: UpdateUser, current_user: dict = Depends(get_current_user)
) -> JSONResponse:
    try:
        db = Database("isc", "users")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        user = user.dict()
        # Update user details
        user["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user["password"] = await hash_key(user["password"])
        updated_user = collection.update_one(
            {"_id": ObjectId(current_user["id"])},
            {"$set": user},
        )
        logging.info(f"User {current_user['username']} updated successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "User details updated successfully",
                "response": "User details updated successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error updating user: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# get top 5 deals
@app.get("/get-top-deals", tags=["deals"])
async def get_top_deals() -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get top 5 deals based on discount_percent
        deals = collection.find().sort("discount_percent", -1).limit(5)
        deals = list(deals)
        for deal in deals:
            deal["_id"] = str(deal["_id"])
            deal["shop_id"] = str(deal["shop_id"])
        logging.info(f"Top 5 deals found: {deals}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Top 5 deals found",
                "response": deals,
            },
        )
    except Exception as e:
        logging.error(f"Error getting top 5 deals: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# search with anything:
@app.get("/search", tags=["deals"])
async def search_deals(search: SearchDeals) -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Search deals based on shop_name
        deals = collection.find(
            {"shop_name": {"$regex": search.shop_name, "$options": "i"}}
        )
        deals = list(deals)
        for deal in deals:
            deal["_id"] = str(deal["_id"])
            deal["shop_id"] = str(deal["shop_id"])
        logging.info(f"Deals found: {deals}")
        await db.close_connection()
        if not deals:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Deals not found",
                    "response": "No deals found",
                },
            )
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deals found",
                "response": deals,
            },
        )
    except Exception as e:
        logging.error(f"Error searching deals: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# ADMIN APIS


# register a new admin
@app.post("/admin-register", tags=["Admin-authentication"])
async def register_admin(data: NewAdminRegistration) -> JSONResponse:
    try:
        db = Database("isc", "owners")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        existing_admin = collection.find_one(
            {"$or": [{"username": data.username}, {"email": data.email}]}
        )
        if existing_admin:
            logging.info(f"Admin with username {data.username} already exists")
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Admin with this username already exists",
                    "response": "Try a different username to register",
                },
            )
        logging.info(f"Admin with username does not exist, creating new admin")

        # Insert admin details into MongoDB
        admin_data = data.dict()
        admin_data.pop("confirm_password")
        admin_data["password"] = await hash_key(data.password)
        admin_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_data["last_updated"] = None
        admin_data["role"] = "admin"
        inserted_admin = collection.insert_one(admin_data)
        logging.info(
            f"Admin registered successfully with id: {inserted_admin.inserted_id}"
        )
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Admin registered successfully",
                "response": "Sign in to continue with our services",
            },
        )
    except Exception as e:
        logging.error(f"Error registering admin: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# FastAPI route for admin login
@app.post("/admin-login", tags=["Admin-authentication"])
async def login_admin(admin_login: UserLogin) -> JSONResponse:
    try:
        # Check if email or username is provided
        if admin_login.email is None and admin_login.username is None:
            return JSONResponse(
                status_code=400,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "email or username is required to login",
                    "response": "Provide valid email or username to login",
                },
            )
    except Exception as e:
        logging.error(f"Error logging in admin: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

    try:
        db = Database("isc", "owners")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Validate admin credentials
        if admin_login.email:
            admin = collection.find_one({"email": admin_login.email})
        else:
            admin = collection.find_one({"username": admin_login.username})
        logging.info(f"Admin found: {admin}")
        if not admin or not bcrypt.checkpw(
            admin_login.password.encode("utf-8"), admin["password"].encode("utf-8")
        ):
            logging.info(
                f"Invalid credentials for admin: {admin_login.email or admin_login.username}"
            )
            return JSONResponse(
                status_code=401,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Invalid credentials",
                    "response": "Please provide valid email/username and password",
                },
            )
        # Generate JWT token
        token_data = {
            "id": str(admin["_id"]),
            "username": admin["username"],
            "email": admin["email"],
            "role": admin["role"],
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=7 * 24 * 60),
            "Last-login": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "custom_data": [],
        }
        token = create_jwt_token(token_data)
        logging.info(f"Admin {admin['username']} logged in successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Admin logged in successfully",
                "response": {"token": token},
            },
        )
    except Exception as e:
        logging.error(f"Error logging in admin: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# get all shops
@app.get("/get-all-shops", tags=["shops"])
async def get_all_shops(
    current_user: dict = Depends(get_current_admin_user),
) -> JSONResponse:
    try:
        db = Database("isc", "shops")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get all shops
        shops = collection.find({"owner": ObjectId(current_user["id"])})
        shops = list(shops)
        for shop in shops:
            shop["_id"] = str(shop["_id"])
            shop["owner"] = str(shop["owner"])
        logging.info(f"Shops found: {shops}")
        await db.close_connection()
        if not shops:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Shops not found",
                    "response": "No shops found",
                },
            )
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Shops found",
                "response": shops,
            },
        )
    except Exception as e:
        logging.error(f"Error getting shops: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# get one shop
@app.get("/get-shop/{shop_id:str}", tags=["shops"])
async def get_shop(
    shop_id: str,
    current_user: dict = Depends(get_current_admin_user)
) -> JSONResponse:
    try:
        db = Database("isc", "shops")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get one shop
        shop = collection.find_one({"_id": ObjectId(shop_id)})
        if not shop:
            logging.info(f"Shop {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Shop not found",
                    "response": "Shop not found",
                },
            )
        shop["_id"] = str(shop["_id"])
        shop["owner"] = str(shop["owner"])
        logging.info(f"Shop found: {shop}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Shop found",
                "response": shop,
            },
        )
    except Exception as e:
        logging.error(f"Error getting shop: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# route to register a NewShopRegistration
@app.post("/new-shop-registration", tags=["shops"])
async def register_shop(
    shop: NewShopRegistration, current_user: dict = Depends(get_current_admin_user)
) -> JSONResponse:
    try:
        db = Database("isc", "shops")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:

        # Insert shop details into MongoDB
        shop_data = shop.dict()
        shop_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        shop_data["last_updated"] = None
        shop_data["owner"] = ObjectId(current_user["id"])
        inserted_shop = collection.insert_one(shop_data)
        logging.info(
            f"Shop registered successfully with id: {inserted_shop.inserted_id}"
        )
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Shop registered successfully",
                "response": "New shop added",
            },
        )
    except Exception as e:
        logging.error(f"Error registering shop: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# route to update the shop details
@app.put("/update-shop/{shop_id:str}", tags=["shops"])
async def update_shop(
    shop: UpdateShop,
    shop_id: str,
    current_user: dict = Depends(get_current_admin_user)
) -> JSONResponse:
    try:
        db = Database("isc", "shops")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        shop = shop.dict(exclude_unset=True)
        # Update shop details
        shop["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_shop = collection.update_one(
            {"_id": ObjectId(shop_id)},
            {"$set": shop},
        )
        logging.info(update_shop)
        if updated_shop.modified_count == 0:
            logging.info(f"Shop {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Shop details not updated",
                    "response": "Shop not found",
                },
            )
        logging.info(f"Shop {current_user['username']} updated successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Shop details updated successfully",
                "response": "Shop details updated successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error updating shop: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# get all deals
@app.get("/get-all-deals/{shop_id:str}", tags=["deals"])
async def get_all_deals(
    shop_id: str,
    current_user: dict = Depends(get_current_admin_user)
) -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # get all deals associated with the shop
        deals = collection.find({"shop_id": ObjectId(shop_id), "is_active": True})
        deals = list(deals)
        for deal in deals:
            deal["_id"] = str(deal["_id"])
            deal["shop_id"] = str(deal["shop_id"])
        logging.info(f"Deals found: {deals}")
        await db.close_connection()
        if not deals:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Deals not found",
                    "response": "No deals found",
                },
            )
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deals found",
                "response": deals,
            },
        )
    except Exception as e:
        logging.error(f"Error getting deals: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# get a deal
@app.get("/get-deal/{deal_id:str}", tags=["deals"])
async def get_deal(
    deal_id: str,
    current_user: dict = Depends(get_current_admin_user),
) -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

    try:
        # Get one deal and check if it is active and end_date has not been surpassed
        deal = collection.find_one({"_id": ObjectId(deal_id), "is_active": True})
        if (
            not deal
            or datetime.strptime(deal["end_date"], "%Y-%m-%d %H:%M:%S") < datetime.now()
        ):
            logging.info(
                f"Deal {deal_id} not found or not active or end_date surpassed"
            )
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "No Deals found",
                    "response": "Deal not found or not active or end_date surpassed",
                },
            )

        deal["_id"] = str(deal["_id"])
        deal["shop_id"] = str(deal["shop_id"])
        logging.info(f"Deal found: {deal}")
        await db.close_connection()

        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deal found",
                "response": deal,
            },
        )
    except Exception as e:
        logging.error(f"Error getting deal: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# create a deal under a shop
@app.post("/create-deal/{shop_id:str}", tags=["deals"])
async def create_deal(
    shop_id: str ,
    deal: RegisterNewDeal,
    current_user: dict = Depends(get_current_admin_user)
) -> JSONResponse:

    #check whether that shop id exists or not   
    try:
        db1 = Database("isc", "shops")
        collection1 = await db1.make_connection()
        shop = collection1.find_one({"_id": ObjectId(shop_id)})
        if not shop:
            logging.info(f"Shop {shop_id} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Shop not found",
                    "response": "Shop not found",
                },
            )
        await db.close_connection()    
        db = Database("isc", "deals")
        collection = await db.make_connection() 
               
    except Exception as e:
        logging.error(f"Error getting shop: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
        
    try:
        # Insert deal details into MongoDB
        deal_data = deal.dict()
        deal_data["is_active"] = True
        deal_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        deal_data["last_updated"] = None
        deal_data["shop_id"] = ObjectId(shop_id)
        inserted_deal = collection.insert_one(deal_data)
        logging.info(f"Deal created successfully with id: {inserted_deal.inserted_id}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deal created successfully",
                "response": "New deal added",
            },
        )
    except Exception as e:
        logging.error(f"Error creating deal: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# update a deal
@app.put("/update-deal/{deal_id:str}", tags=["deals"])
async def update_deal(
    deal: UpdateDeal,
    deal_id: str,
    current_user: dict = Depends(get_current_admin_user),
    
) -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

    try:
        deal = deal.dict(exclude_unset=True)
        # Update deal details
        deal["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_deal = collection.update_one(
            {"_id": ObjectId(deal_id)},
            {"$set": deal},
        )

        if updated_deal.modified_count == 0:
            logging.info(f"Deal {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Deal details not updated",
                    "response": "Deal not found",
                },
            )
        logging.info(f"Deal {current_user['username']} updated successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deal details updated successfully",
                "response": "Deal details updated successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error updating deal: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# delete a deal
@app.delete("/delete-deal/{deal_id:str}", tags=["deals"])
async def delete_deal(
    deal_id: str,
    current_user: dict = Depends(get_current_admin_user),
) -> JSONResponse:
    try:
        db = Database("isc", "deals")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    # updating is_active to False
    try:
        updated_deal = collection.update_one(
            {"_id": ObjectId(deal_id)},
            {"$set": {"is_active": False}},
        )

        if updated_deal.modified_count == 0:
            logging.info(f"Deal {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Deal not deleted",
                    "response": "Deal not found",
                },
            )
        logging.info(f"Deal {current_user['username']} deleted successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Deal deleted successfully",
                "response": "Deal deleted successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error deleting deal: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )





#gateways and beacon apis
# 1. GET /gateways
#    - Description: Get information about all gateways associated with that shop_id.
#    - Response: List of gateway objects.


@app.get("/all-gateways/{shop_owner_id:str}", tags=["gateways"])
async def get_gateways(shop_owner_id:str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "gateways")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get all gateways associated with the shop
        gateways = collection.find({"shop_owner_id": ObjectId(shop_owner_id)})
        gateways = list(gateways)
        for gateway in gateways:
            gateway["_id"] = str(gateway["_id"])
            gateway["shop_owner_id"] = str(gateway["shop_owner_id"])
        logging.info(f"Gateways found: {gateways}")
        await db.close_connection()
        if not gateways:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Gateways not found",
                    "response": "No gateways found",
                },
            )
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Gateways found",
                "response": gateways,
            },
        )
    except Exception as e:
        logging.error(f"Error getting gateways: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    
        
        

# 2. GET /gateways/?{gateway_id}
#    - Description: Get information about a specific gateway.
#    - Response: Gateway object.

@app.get("/gateways/{gateway_id:str}", tags=["gateways"])
async def get_gateway(gateway_id:str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "gateways")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get one gateway
        gateway = collection.find_one({"_id": ObjectId(gateway_id)})
        logging.info(f"Gateway found: {gateway}")
        if not gateway:
            logging.info(f"Gateway {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Gateway not found",
                    "response": "Gateway not found",
                },
            )
        gateway["_id"] = str(gateway["_id"])
        gateway["shop_owner_id"] = str(gateway["shop_owner_id"])
        logging.info(f"Gateway found: {gateway}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Gateway found",
                "response": gateway,
            },
        )
    except Exception as e:
        logging.error(f"Error getting gateway: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )   
    


# 3. POST /gateways
#    - Description: Add a new gateway to a specific shop.
#    - Request Body: List of gateway objects.
#    - Response: success/failure.

@app.post("/register-gateways/{shop_owner_id:str}", tags=["gateways"])
async def register_gateway( gateway: NewGatewayRegistration, shop_owner_id: str, current_user: dict = Depends(get_current_admin_user)):
    #check whether that shop id exists or not
    try:
        db1 = Database("isc", "shops")
        collection1 = await db1.make_connection()
        shop = collection1.find_one({"_id": ObjectId(shop_owner_id)})
        if not shop:
            logging.info(f"Shop {shop_owner_id} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Shop not found",
                    "response": "Shop not found",
                },
            )
        await db1.close_connection()
    except Exception as e:
        logging.error(f"Error getting shop: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        db = Database("isc", "gateways")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Insert gateway details into MongoDB
        gateway_data = gateway.dict()
        gateway_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        gateway_data["last_updated"] = None
        gateway_data["shop_owner_id"] = ObjectId(shop_owner_id)
        inserted_gateway = collection.insert_one(gateway_data)
        logging.info(f"Gateway created successfully with id: {inserted_gateway.inserted_id}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Gateway created successfully",
                "response": "New gateway added",
            },
        )
    except Exception as e:
        logging.error(f"Error creating gateway: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# 4. PUT /gateways/?{gateway_id}
#    - Description: Update information about a specific gateway.
#    - Request Body: Updated gateway object.
#    - Response: Updated gateway object.

@app.put("/update-gateways/{gateway_id:str}", tags=["gateways"])
async def update_gateway( gateway: GatewayUpdate, gateway_id: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "gateways")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        gateway = gateway.dict(exclude_unset=True)
        # Update gateway details
        gateway["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_gateway = collection.update_one(
            {"_id": ObjectId(gateway_id)},
            {"$set": gateway},
        )

        if updated_gateway.modified_count == 0:
            logging.info(f"Gateway {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Gateway details not updated",
                    "response": "Gateway not found",
                },
            )
        logging.info(f"Gateway {current_user['username']} updated successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Gateway details updated successfully",
                "response": "Gateway details updated successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error updating gateway: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# 5. GET /all-beacons
#    - Description: Get information about all beacons associated with the gateway_id.
#    - Response: List of beacon objects.

@app.get("/all-beacons/{gateway_owner_id:str}", tags=["beacons"])
async def get_beacons(gateway_owner_id: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "beacons")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get all beacons associated with the gateway
        beacons = collection.find({"gateway_owner_id": ObjectId(gateway_owner_id)})
        beacons = list(beacons)
        for beacon in beacons:
            beacon["_id"] = str(beacon["_id"])
            beacon["gateway_owner_id"] = str(beacon["gateway_owner_id"])
        logging.info(f"Beacons found: {beacons}")
        await db.close_connection()
        if not beacons:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Beacons not found",
                    "response": "No beacons found",
                },
            )
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Beacons found",
                "response": beacons,
            },
        )
    except Exception as e:
        logging.error(f"Error getting beacons: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# 6. GET /beacons/{beacon_id}
#    - Description: Get information about a specific beacon.
#    - Response: Beacon object.

@app.get("/beacons/{beacon_id:str}", tags=["beacons"])
async def get_beacon(beacon_id: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "beacons")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Get one beacon
        beacon = collection.find_one({"_id": ObjectId(beacon_id)})
        if not beacon:
            logging.info(f"Beacon {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Beacon not found",
                    "response": "Beacon not found",
                },
            )
        beacon["_id"] = str(beacon["_id"])
        beacon["gateway_owner_id"] = str(beacon["gateway_owner_id"])
        logging.info(f"Beacon found: {beacon}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Beacon found",
                "response": beacon,
            },
        )
    except Exception as e:
        logging.error(f"Error getting beacon: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

# 7. POST /beacons
#    - Description: Add a new beacon and associated it with particular gateway_owner_id .
#    - Request Body: List of beacon objects.
#    - Response: List of created beacon objects.

@app.post("/add-beacons/{gateway_owner_id:str}", tags=["beacons"])
async def register_beacon( beacon: NewBeaconRegistration, gateway_owner_id: str, current_user: dict = Depends(get_current_admin_user)):
    
    #check whether that gateway id exists or not
    try:
        db1 = Database("isc", "gateways")
        collection1 = await db1.make_connection()
        gateway = collection1.find_one({"_id": ObjectId(gateway_owner_id)})
        if not gateway:
            logging.info(f"Gateway {gateway_owner_id} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Gateway not found, please provide correct details",
                    "response": "Gateway not found",
                },
            )
        await db1.close_connection()
    except Exception as e:
        logging.error(f"Error getting gateway: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    
    try:
        db = Database("isc", "beacons")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Insert beacon details into MongoDB
        beacon_data = beacon.dict()
        beacon_data["registered_on"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        beacon_data["last_updated"] = None
        beacon_data["gateway_owner_id"] = ObjectId(gateway_owner_id)
        inserted_beacon = collection.insert_one(beacon_data)
        logging.info(f"Beacon created successfully with id: {inserted_beacon.inserted_id}")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Beacon created successfully",
                "response": "New beacon added",
            },
        )
    except Exception as e:
        logging.error(f"Error creating beacon: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )


# 8. PUT /beacons/{beacon_id}
#    - Description: Update information about a specific beacon.
#    - Request Body: Updated beacon object.
#    - Response: Updated beacon object.

@app.put("/update-beacons/{beacon_id:str}", tags=["beacons"])
async def update_beacon( beacon: BeaconUpdate, beacon_id: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "beacons")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        beacon = beacon.dict(exclude_unset=True)
        # Update beacon details
        beacon["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_beacon = collection.update_one(
            {"_id": ObjectId(beacon_id)},
            {"$set": beacon},
        )

        if updated_beacon.modified_count == 0:
            logging.info(f"Beacon {current_user['username']} not found")
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Beacon details not updated",
                    "response": "Beacon not found",
                },
            )
        logging.info(f"Beacon {current_user['username']} updated successfully")
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Beacon details updated successfully",
                "response": "Beacon details updated successfully",
            },
        )
    except Exception as e:
        logging.error(f"Error updating beacon: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )

#get-everything about user
@app.get("/get-everything", tags=["everything"])
async def get_all_details(owner_id:str=None, page: int = 1, page_size: int = 10, current_user: dict = Depends(get_current_admin_user)):
    try:
        db = Database("isc", "owners")
        collection = await db.make_connection()
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
    try:
        # Initialize the pipeline
        pipeline = []

        # If owner_id is provided, add a $match stage to the pipeline
        if owner_id is not None:
            # Convert owner_id string to ObjectId
            owner_id = ObjectId(owner_id)
            pipeline.append({"$match": {"_id": owner_id}})

        # Add the remaining stages to the pipeline
        pipeline.extend([
            {"$lookup": {
                "from": "shops",
                "let": {"owner_id": "$_id"},
                "pipeline": [
                    {"$match": {"$expr": {"$eq": ["$owner", "$$owner_id"]}}},
                    {"$lookup": {
                        "from": "deals",
                        "let": {"shop_id": "$_id"},
                        "pipeline": [
                            {"$match": {"$expr": {"$eq": ["$shop_id", "$$shop_id"]}}},
                            {"$sort": {"registered_on": -1}}
                        ],
                        "as": "deals"
                    }},
                    {"$lookup": {
                        "from": "gateways",
                        "let": {"shop_owner_id": "$_id"},
                        "pipeline": [
                            {"$match": {"$expr": {"$eq": ["$shop_owner_id", "$$shop_owner_id"]}}},
                            {"$lookup": {
                                "from": "beacons",
                                "let": {"gateway_owner_id": "$_id"},
                                "pipeline": [
                                    {"$match": {"$expr": {"$eq": ["$gateway_owner_id", "$$gateway_owner_id"]}}},
                                    {"$sort": {"registered_on": -1}}
                                ],
                                "as": "beacons"
                            }},
                            {"$sort": {"registered_on": -1}}
                        ],
                        "as": "gateways"
                    }},
                    {"$sort": {"registered_on": -1}}
                ],
                "as": "shops"
            }},
            {"$project": {
                "password": 0,
                "shops.deals.shop_id": 0,
                "shops.gateways.shop_owner_id": 0,
                "shops.gateways.beacons.gateway_owner_id": 0
            }},
            {"$skip": page_size * (page - 1)},  # Skip the documents that come before the current page
            {"$limit": page_size},  # Limit the number of documents to the page size
        ])

        result = list(collection.aggregate(pipeline))
        # Convert ObjectId to string for JSON serialization
        for doc in result:
            if isinstance(doc.get('_id'), ObjectId):
                doc['_id'] = str(doc.get('_id'))
            doc['registered_on'] = doc.get('registered_on').strftime("%Y-%m-%d %H:%M:%S") if isinstance(doc.get('registered_on'), datetime) else None
            doc['last_updated'] = doc.get('last_updated').strftime("%Y-%m-%d %H:%M:%S") if isinstance(doc.get('last_updated'), datetime) else None
            for shop in doc.get('shops', []):
                if isinstance(shop.get('_id'), ObjectId):
                    shop['_id'] = str(shop.get('_id'))
                    shop['owner'] = str(shop.get('owner'))
                shop['registered_on'] = shop.get('registered_on').strftime("%Y-%m-%d %H:%M:%S") if isinstance(shop.get('registered_on'), datetime) else None
                shop['last_updated'] = shop.get('last_updated').strftime("%Y-%m-%d %H:%M:%S") if isinstance(shop.get('last_updated'), datetime) else None
                for deal in shop.get('deals', []):
                    if isinstance(deal.get('_id'), ObjectId):
                        deal['_id'] = str(deal.get('_id'))
                    deal['start_date'] = deal.get('start_date').strftime("%Y-%m-%d %H:%M:%S") if isinstance(deal.get('start_date'), datetime) else None
                    deal['end_date'] = deal.get('end_date').strftime("%Y-%m-%d %H:%M:%S") if isinstance(deal.get('end_date'), datetime) else None
                    deal['registered_on'] = deal.get('registered_on').strftime("%Y-%m-%d %H:%M:%S") if isinstance(deal.get('registered_on'), datetime) else None
                    deal['last_updated'] = deal.get('last_updated').strftime("%Y-%m-%d %H:%M:%S") if isinstance(deal.get('last_updated'), datetime) else None
                for gateway in shop.get('gateways', []):
                    if isinstance(gateway.get('_id'), ObjectId):
                        gateway['_id'] = str(gateway.get('_id'))
                    gateway['registered_on'] = gateway.get('registered_on').strftime("%Y-%m-%d %H:%M:%S") if isinstance(gateway.get('registered_on'), datetime) else None
                    gateway['last_updated'] = gateway.get('last_updated').strftime("%Y-%m-%d %H:%M:%S") if isinstance(gateway.get('last_updated'), datetime) else None
                    for beacon in gateway.get('beacons', []):
                        if isinstance(beacon.get('_id'), ObjectId):
                            beacon['_id'] = str(beacon.get('_id'))
                        beacon['registered_on'] = beacon.get('registered_on').strftime("%Y-%m-%d %H:%M:%S") if isinstance(beacon.get('registered_on'), datetime) else None
                        beacon['last_updated'] = beacon.get('last_updated').strftime("%Y-%m-%d %H:%M:%S") if isinstance(beacon.get('last_updated'), datetime) else None

        logging.info(f"Data found: {result}")
        if not result:
            return JSONResponse(
                status_code=404,
                media_type="application/json",
                content={
                    "status": False,
                    "message": "Data not found",
                    "response": "No data found",
                },
            )
        # Return the result
        await db.close_connection()
        return JSONResponse(
            status_code=200,
            media_type="application/json",
            content={
                "status": True,
                "message": "Data found",
                "response": jsonable_encoder(result),
            },
        )
    except Exception as e:
        logging.error(f"Error getting everything: {e}")
        return JSONResponse(
            status_code=500,
            media_type="application/json",
            content={
                "status": False,
                "message": "Internal server error",
                "response": "There is some issue with our services, please try again later",
            },
        )
