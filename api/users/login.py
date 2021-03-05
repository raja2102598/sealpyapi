from flask import make_response
from flask_restful import Resource
import pymysql
from config import *
from flask_restful.reqparse import RequestParser
from seal import *
from seal_helper import *
import hashlib 
import time

# db = pymysql.connect(host=HOST,
#                     user=USER,
#                     password=PASSWORD,
#                     db=MASTERDATABASE,
#                     charset=CHARSET,
#                     cursorclass=pymysql.cursors.DictCursor)

# # Temporary db work area
# cursor = db.cursor()

validate_login = RequestParser(bundle_errors=True)
validate_login.add_argument('email', type=str, required=True, help='Email is required')
validate_login.add_argument('password', type=str, required=True, help='Password is required')
validate_login.add_argument('password1', type=str, required=True, help='Password1 is required')

class login(Resource):
    def post(self):
        args = validate_login.parse_args()
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
        value1 = hash(args['password'])
        value2 = hash(args['password1'])
        # print(value1)
        # print(value2)
        plain1 = Plaintext(encoder.encode(value1))
        plain2 = Plaintext(encoder.encode(value2))
        
        encrypted1 = Ciphertext()
        encrypted2 = Ciphertext()
        
        encryptor.encrypt(plain1, encrypted1)
        encryptor.encrypt(plain2, encrypted2)
        
        result1=Plaintext()
        result2=Plaintext()
        
        decryptor.decrypt(encrypted1,result1)
        decryptor.decrypt(encrypted2,result2)
        if(str(encoder.decode_int64(result1))==str(encoder.decode_int64(result2))):
            print("true")
            return make_response({"status":0,"message":"Login success"})
        else:
            return make_response({"status":1,"message":"Login failed"})