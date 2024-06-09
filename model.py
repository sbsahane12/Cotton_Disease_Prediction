from pymongo import MongoClient
from passlib.hash import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        client = MongoClient(os.getenv('MONGO_DB'))
        self.db = client[os.getenv('DB_NAME')]
        self.users_collection = self.db['users']
        self.contacts_collection = self.db['contacts']

    def get_user_by_email(self, email):
        return self.users_collection.find_one({'email': email})

    def insert_user(self, user):
        user.password_hash = bcrypt.hash(user.password)
        self.users_collection.insert_one(user.to_dict())

    def get_all_users(self):
        return list(self.users_collection.find())

    def update_user(self, email, updated_user):
        if updated_user.password:
            updated_user.password_hash = bcrypt.hash(updated_user.password)
        self.users_collection.update_one({'email': email}, {'$set': updated_user.to_dict()})

    def delete_user(self, email):
        self.users_collection.delete_one({'email': email})

    def insert_contact(self, contact):
        self.contacts_collection.insert_one(contact.to_dict())

    def get_all_contacts(self):
        return list(self.contacts_collection.find())

    def delete_contact(self, contact_id):
        self.contacts_collection.delete_one({'_id': contact_id})

    def mark_contact_as_seen(self, contact_id):
        self.contacts_collection.update_one({'_id': contact_id}, {'$set': {'seen': True}})


    

class User:
    def __init__(self, username, email, password, is_admin=False, is_verified=False):
        self.username = username
        self.email = email
        self.password = password
        self.is_admin = is_admin
        self.is_verified = is_verified

    def to_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'password_hash': bcrypt.hash(self.password) if self.password else None,
            'is_admin': self.is_admin,
            'is_verified': self.is_verified
        }

class Contact:
    def __init__(self, name, email, message, seen=False):
        self.name = name
        self.email = email
        self.message = message
        self.seen = seen

    def to_dict(self):
        return {
            'name': self.name,
            'email': self.email,
            'message': self.message,
            'seen': self.seen
        }