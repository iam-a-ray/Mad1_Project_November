from dotenv import load_dotenv
# for reading data base for app
import os
# os for reading secrets from env file which  is used to provide secret to app 
from app import app 
# first app is for app.py second one is app name
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
