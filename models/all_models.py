from pydantic import BaseModel
from typing import Optional, List
from pydantic import BaseModel, Field



# Model for user registration
class NewUserRegistration(BaseModel):
    username: str = Field(..., min_length=4)
    first_name: str = Field(..., min_length=2)
    last_name: str = Field(..., min_length=2)
    email: str = Field(..., min_length=5, pattern="^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    phone: Optional[str] = None
    password: str = Field(..., min_length=8, max_length=16)
    class Config:
        extra = 'forbid'

# Model for user login
class UserLogin(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str
    class Config:
        extra = 'forbid'

# Model for updating user details
class UpdateUser(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    class Config:
        extra = 'forbid' 





#Below are the models for the ADMINs and Organizations

#shops    
class Coordinates(BaseModel):
    lat: float
    long: float

class Location(BaseModel):
    city: str
    state: str
    country: str
    zipcode: str
    coordinates: Coordinates
 
class NewShopRegistration(BaseModel):
    c_type: str
    location: Location
    contact: str
    floor_number: int
    store_name: str
    store_number: int
    categories: List[str]
    website: str


class UpdateLocation(BaseModel):
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    zipcode: Optional[str] = None
    coordinates: Optional[Coordinates] = None
    class Config:
        extra = 'forbid'

class UpdateShop(BaseModel):
    c_type: Optional[str] = None
    location: Optional[UpdateLocation] = None
    contact: Optional[str] = None
    floor_number: Optional[int] = None
    store_name: Optional[str] = None
    store_number: Optional[int] = None
    categories: Optional[List[str]] = None
    website: Optional[str] = None
    class Config:
        extra = 'forbid'

#deals
class RegisterNewDeal(BaseModel):
    deal_name: str
    discount_percent: int
    start_date: str
    end_date: str
    categories: str

class UpdateDeal(BaseModel):
    deal_name: Optional[str] = None
    discount_percent: Optional[int] = None
    is_active: Optional[bool] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    categories: Optional[str] = None
    class Config:
        extra = 'forbid'

# Model for searching deals
class SearchDeals(BaseModel):
    shop_name: Optional[str] = None
    city: Optional[str] = None
    zipcode: Optional[str] = None
    store_name: Optional[str] = None
    category: Optional[str] = None
    deal_name: Optional[str] = None
    deal_category: Optional[str] = None


# Admin registration
class SecurityQuestion(BaseModel):
    question: str
    answer: str

class Address(BaseModel):
    street: str
    city: str
    state: str
    zip_code: str 
    country: str

class NewAdminRegistration(BaseModel):
    email: str
    username: str
    password: str
    confirm_password: str 
    first_name: str 
    last_name: str 
    gender: str
    profile_picture: Optional[str] 
    phone_number: str 
    security_information: Optional[SecurityQuestion]
    address: Address

    class Config:
        extra = 'forbid'

