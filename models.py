from sqlalchemy import Column,Integer,String, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
	__tablename__ = 'user'
	user_id = Column(Integer, primary_key = True)
	username = Column(String)
	user_email = Column(String, index = True)
	user_picture = Column(String)

	def generate_auth_token(self, expiration=600):
		s = Serializer(secret_key, expires_in = expiration)
		return s.dumps({'id': self.user_id })

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(secret_key)
		try:
			data = s.loads(token)
		except SignatureExpired:
			#Valid Token, but expired
			return None
		except BadSignature:
			#Invalid Token
			return None
		user_id = data['id']
		return user_id

class Category(Base):
	__tablename__ = 'category'
	category_id = Column(Integer, primary_key = True)
	category_name = Column(String, index = True)
	user_id = Column(Integer, ForeignKey('user.user_id'))
	user = relationship(User)
	create_time = Column(TIMESTAMP, server_default=func.now())
	update_time = Column(TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())

	@property
	def serialize(self):
		return {
			'category_id': self.category_id,
			'category_name': self.category_name,
			'user_id': self.user_id,
			'create_time': self.create_time,
			'update_time': self.update_time
		}

class Item(Base):
	__tablename__ = 'item'
	item_id = Column(Integer, primary_key = True)
	item_name = Column(String)
	item_description = Column(String)
	category_id = Column(Integer, ForeignKey('category.category_id'))
	category = relationship(Category)
	user_id = Column(Integer, ForeignKey('user.user_id'))
	user = relationship(User)
	create_time = Column(TIMESTAMP, server_default=func.now())
	update_time = Column(TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())

	@property
	def serialize(self):
		return {
			'item_id': self.item_id,
			'item_name': self.item_name,
			'item_description': self.item_description,
			'category_id': self.category_id,
			'user_id': self.user_id,
			'create_time': self.create_time,
			'update_time': self.update_time
		}

engine = create_engine('sqlite:///item-catalog.db')

Base.metadata.create_all(engine)