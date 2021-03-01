from flask import Flask
from seal import *
from seal_helper import *
import numpy as np
import sqlite3,json
app = Flask(__name__)
    
@app.route('/')
def main():
        return "Hello";
# @app.route('/login/<username>',methods=['POST'])
# def postLogin(username):
#     connection = sqlite3.connect('./test.db')
#     try:
#         c = connection.cursor()
#         s=c.execute('INSERT INTO login(name) VALUES(?)',(username,))
#         connection.commit()
#         if s.rowcount>0:
#             return json.dumps({"status": "Success", "message": "Data inserted in table"})
#         else:
#             return json.dumps({"status": "Failed", "message": "Data can't be inserted"})
#     finally:
#         connection.close()

@app.route('/test')
def example():
    print('hello')
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
    value1 = hash('raja')
    print(value1)
    plain1 = Plaintext(encoder.encode(value1))
    encrypted1 = Ciphertext()
    encryptor.encrypt(plain1, encrypted1)
    result=Plaintext()
    decryptor.decrypt(encrypted1,result)
    # print(result.to_string())
    print(str(encoder.decode_int64(result)))
    # str(encoder.decode_int32(plain_result)) + "...... Correct.")
    # return str(encoder.decode_int32(plain_result))
    return "hello"