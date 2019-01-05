from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer)
from itsdangerous import BadSignature, SignatureExpired

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))  # noqa


# Categories Table
class Categories(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    user_id = Column(Integer)

    @property
    def serialize(self):
        return {
                'id': self.id,
                'name': self.name
        }


# Items Table
class Items(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    picture = Column(String)
    cat_id = Column(Integer, ForeignKey('categories.id'))
    category = Column(String)
    categories = relationship(Categories, backref='items')
    user_id = Column(Integer)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'picture': self.picture,
            'category': self.category,
            'user_id': self.user_id
        }


# Users Table
class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    password_hash = Column(String)
    email = Column(String)
    picture = Column(String)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
            print(data)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


engine = create_engine('sqlite:///catalog.db',
                       connect_args={'check_same_thread': False},
                       poolclass=StaticPool)
Base.metadata.create_all(engine)
