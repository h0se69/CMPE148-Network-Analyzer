import os
from flask import Flask

flaskObj = Flask(__name__)
flaskObj.config['SECRET_KEY'] = 'your_secret_key'

from CMPE148_Network_App import routes
