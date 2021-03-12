from flask import Flask
from flask_restful import Api
from api.users.login import login
from api.search.searchUsers import searchAge
from api.search.searchCity import searchCity
import numpy as np
import sqlite3,json


app = Flask(__name__)
api = Api(app, prefix='/api/v1')

@app.route('/')
def main():
    return '<center><h1>Seal Python </h1></center>'

# API Resources
api.add_resource(login, '/login')

api.add_resource(searchAge,'/searchAge')

api.add_resource(searchCity,'/searchCity')

if __name__ == '__main__':
    # app.run(host='0.0.0.0') 
    app.run(host='127.0.0.1',port=4000, debug=True)