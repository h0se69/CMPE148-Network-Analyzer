import os
from flask import Flask

flaskObj = Flask(__name__)
flaskObj.config['SECRET_KEY'] = os.urandom(24)  # Set a secret key for session security

from CMPE148_Network_App import routes
