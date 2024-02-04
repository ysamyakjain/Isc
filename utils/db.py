import logging
import os
from pymongo import MongoClient

# Configure logging
logging.basicConfig(level=logging.INFO)

class Database:
    def __init__(self, database_name, collection_name):
        # Set default MongoDB connection details
        self._database_url = "mongodb+srv://admin:jMDXIAST8Xkgli7M@cluster0.s2rmagk.mongodb.net/?retryWrites=true&w=majority"
        self._database_name = database_name
        self._collection_name = collection_name

    async def make_connection(self):
        try:
            # Initialize MongoDB connection
            self._client = MongoClient(self._database_url)
            self._db = self._client[self._database_name]
            self._collection = self._db[self._collection_name]
            logging.info("Connected to MongoDB")
            return self._collection
        except Exception as e:
            logging.error(f"Error connecting to MongoDB: {e}")

    async def close_connection(self):
        try:
            self._client.close()
            logging.info("Closed MongoDB connection")
        except Exception as e:
            logging.error(f"Error closing MongoDB connection: {e}")
