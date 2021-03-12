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


validate_search = RequestParser(bundle_errors=True)
validate_search.add_argument('age', type=str, required=True, help='age is required')
validate_search.add_argument('userid', type=str, required=True, help='userid is required')
validate_search.add_argument('age1', type=str, required=True, help='age1 is required')

class searchAge(Resource):
    def post(self):
        args = validate_search.parse_args()
        print(args['age1'])
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
        def encryptorAge(value):
            ageVal=hash(value)
            age=Plaintext(encoder.encode(ageVal))
            ageEnc=Ciphertext()
            encryptor.encrypt(age,ageEnc)
            res=Plaintext()
            decryptor.decrypt(ageEnc,res)
            return encoder.decode_int64(res)
        def hashFun(val):
            return hashlib.md5(str(val).encode('utf-8')).hexdigest()

        value1 = hash(args['age'])
        value2 = hash(args['age1'])

        # print(value1)
        # print(value2)
        
        plain1 = Plaintext(encoder.encode(value1))
        plain2 = Plaintext(encoder.encode(value2))
        
        encrypted1 = Ciphertext()
        encrypted2 = Ciphertext()
        # x_squared1 = Ciphertext()
        # x_squared2 = Ciphertext()
        
        encryptor.encrypt(plain1, encrypted1)
        encryptor.encrypt(plain2, encrypted2)
        # evaluator.square(encrypted1, x_squared1)
        # evaluator.square(encrypted2, x_squared2)        
        
        result1=Plaintext()
        result2=Plaintext()
        # 6f4922f45568161a8cdf4ad2299f6d23
        # 6f4922f45568161a8cdf4ad2299f6d23 
        
        decryptor.decrypt(encrypted1,result1)
        decryptor.decrypt(encrypted2,result2)
        # print(str(encoder.decode_int64(result1)))
        # print(str(encoder.decode_int64(result2)))
       
        # print(hashFun(18))
        # print(str(encryptorAge("18")))
        # print(encryptorAge(hashFun(18)))

        if(str(encoder.decode_int64(result1))==str(encryptorAge(hashFun(18)))):
            for i in range(1,18):
                # print(str(encryptorAge(str(i))))
                if(str(encoder.decode_int64(result2))==str(encryptorAge(hashFun(i)))):
                    print(i)
                    return make_response({"status":0,"message":"True","userid":args['userid']})
            else:
                return make_response({"status":1,"message":"False","userid":args['userid']})
        if(str(encoder.decode_int64(result1))==str(encryptorAge(hashFun(29)))):
            for i in range(18,29):
                # print(str(encryptorAge(str(i))))
                if(str(encoder.decode_int64(result2))==str(encryptorAge(hashFun(i)))):
                    print(i)
                    return make_response({"status":0,"message":"True","userid":args['userid']})
            else:
                return make_response({"status":1,"message":"False","userid":args['userid']})
        if(str(encoder.decode_int64(result1))==str(encryptorAge(hashFun(39)))):
            for i in range(29,39):
                # print(str(encryptorAge(str(i))))
                if(str(encoder.decode_int64(result2))==str(encryptorAge(hashFun(i)))):
                    print(i)
                    return make_response({"status":0,"message":"True","userid":args['userid']})
            else:
                return make_response({"status":1,"message":"False","userid":args['userid']})
        if(str(encoder.decode_int64(result1))==str(encryptorAge(hashFun(49)))):
            for i in range(39,49):
                # print(str(encryptorAge(str(i))))
                if(str(encoder.decode_int64(result2))==str(encryptorAge(hashFun(i)))):
                    print(i)
                    return make_response({"status":0,"message":"True","userid":args['userid']})
            else:
                return make_response({"status":1,"message":"False","userid":args['userid']})
        if(str(encoder.decode_int64(result1))==str(encryptorAge(hashFun(50)))):
            for i in range(49,80):
                # print(str(encryptorAge(str(i))))
                if(str(encoder.decode_int64(result2))==str(encryptorAge(hashFun(i)))):
                    print(i)
                    return make_response({"status":0,"message":"True","userid":args['userid']})
            else:
                return make_response({"status":1,"message":"False","userid":args['userid']})