from flask import make_response
from flask_restful import Resource
import pymysql
from config import *
from flask_restful.reqparse import RequestParser
from seal import *
from seal_helper import *
import hashlib 
import time
# import json

# db = pymysql.connect(host=HOST,
#                     user=USER,
#                     password=PASSWORD,
#                     db=MASTERDATABASE,
#                     charset=CHARSET,
#                     port=3306,
#                     cursorclass=pymysql.cursors.DictCursor)

# # Temporary db work area
# # cursor = db.cursor()
# with db.cursor() as cursor:
#         # Read a single record
#         sql = "SELECT * FROM `user_profile` WHERE `u_email`=%s"
#         cursor.execute(sql, ('subash@gmail.com',))
#         result = cursor.fetchone()
#         print(result)


validate_searchCity = RequestParser(bundle_errors=True)
validate_searchCity.add_argument('userid', type=str, required=True, help='userid is required')
validate_searchCity.add_argument('city1', type=str, required=True, help='city1 is required')
validate_searchCity.add_argument('city', type=str, required=True, help='city is required')

class searchCity(Resource):
    def post(self):
        args = validate_searchCity.parse_args()
        # print(args['age1'])
        print(args['city'])
        print(args['city1'])
        parms = EncryptionParameters(scheme_type.BFV)
        poly_modulus_degree = 4096
        parms.set_poly_modulus_degree(poly_modulus_degree)
        parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
        parms.set_plain_modulus(512)
        context = SEALContext.Create(parms)
        keygen = KeyGenerator(context)
        public_key = keygen.public_key()
        secret_key = keygen.secret_key()
        encryptor = Encryptor(context, public_key)
        evaluator = Evaluator(context)
        decryptor = Decryptor(context, secret_key)
        encoder = IntegerEncoder(context)
        def encryptorCity(value):
            cityVal=hash(value)
            city=Plaintext(encoder.encode(cityVal))
            cityEnc=Ciphertext()
            encryptor.encrypt(city,cityEnc)
            res=Plaintext()
            decryptor.decrypt(cityEnc,res)
            return encoder.decode_int64(res)
        print(encryptorCity(args['city']))
        print(encryptorCity(args['city1']))
        if(str(encryptorCity(args['city']))==str(encryptorCity(args['city1']))):
            return make_response({"status":0,"message":"True","userid":args['userid']})
        else:
            return make_response({"status":1,"message":"False","userid":args['userid']})
