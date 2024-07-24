import random
import uuid
import json
import base64
import requests
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA1
import os
import logging
import pytz
from collections import defaultdict

logging.basicConfig(filename='logs/efris_logfile.log', level=logging.DEBUG)

def main():
    logging.info("Starting...")
    # resp_content = make_post("T106", fdn_query_all_invoices_summary_T106)
    resp_content = make_post("T128", fdn_query_stock_quantity_by_ID_T128)
    # resp_content = make_post("T144",fdn_batch_query_goods_T144)
    # resp_content = make_post("T108", fdn_query_one_invoice_details_T108)
    logging.info(f"Main response: {resp_content}")

random_integer = random.randint(1, 1000000)
#324009633259
#324009633736

fdn_query_all_invoices_summary_T106 ={
            "invoiceType": "1",
            "startDate": "2024-06-17",
            "endDate": "",
            "pageNo": "1",
            "pageSize": "10"
            
        }
fdn_query_one_invoice_details_T108 ={  "invoiceNo": "324009633259"    }
fdn_query_stock_quantity_by_ID_T128 ={
                "branchId":"799150987600117988",
                "id":"AZHAR LASER 070G A4 5RM PACK"
            }
fdn_batch_query_goods_T144 ={
                "goodsCode":"0008598986,0008598999,14111601",
                "tin":"1017460267"
            }


def efris_log_info(message):
    logging.info(message)

def efris_log_warning(message):
    logging.warning(message)

def efris_log_error(message):
    logging.error(message)

def make_post(interfaceCode, content):
    try:
        data = fetch_data()
        efris_log_info("Data fetched successfully")

        aes_key = get_AES_key()
        efris_log_info("AES key fetched successfully")

        deviceNo = "1017460267_01"
        tin = "1017460267"
        brn = ""

        json_content = json.dumps(content)
        efris_log_info("Content converted to JSON successfully: " + json_content)

        isAESEncrypted = encrypt_aes_ecb(json_content, aes_key)
        efris_log_info("Content encrypted with AES successfully")

        isAESEncrypted = base64.b64decode(isAESEncrypted)
        newEncrypteddata = base64.b64encode(isAESEncrypted).decode("utf-8")

        if isAESEncrypted:
            efris_log_info("AES encryption successful")
            data["globalInfo"]["deviceNo"] = deviceNo
            data["globalInfo"]["tin"] = tin
            data["globalInfo"]["brn"] = brn
            data["globalInfo"]["interfaceCode"] = interfaceCode
            data["data"]["content"] = base64.b64encode(isAESEncrypted).decode("utf-8")
            data["data"]["dataDescription"] = {"codeType": "1", "encryptCode": "2"}

            private_key = get_private_key()
            efris_log_info("Private key fetched successfully in make_post()")

            signature = sign_data(private_key, newEncrypteddata.encode())
            efris_log_info("signature done...")

            if signature:
                b4signature = base64.b64encode(signature).decode()
                data["data"]["signature"] = b4signature

        data_json = json.dumps(data).replace("'", '"').replace("\n", "").replace("\r", "")
        efris_log_info("Request data converted to JSON successfully")
        efris_log_info("Request data:\n")
        efris_log_info(data_json)

        json_resp = post_req(data_json)

        resp = json.loads(json_resp)
        efris_log_info("Server response successfully parsed")

        errorMsg = resp["returnStateInfo"]["returnMessage"]
        efris_log_info("returnStateInfoMsg: " + errorMsg)
        if errorMsg != "SUCCESS":
            return False, errorMsg

        respcontent = resp["data"]["content"]
        efris_response = decrypt_aes_ecb(aes_key, respcontent)
        efris_log_info("Response content decrypted successfully")
        resp_json = json.loads(efris_response)
        efris_log_info("Decrypted JSON Data:")
        efris_log_info(resp_json)
        return True, resp_json

    except Exception as e:
        efris_log_error("An error occurred: " + str(e))
        return False, str(e)

def encrypt_aes_ecb(data, key):
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    padded_data = data + padding.decode()

    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(padded_data.encode("utf-8"))
    ct = base64.b64encode(ct_bytes).decode("utf-8")
    return ct

def decrypt_aes_ecb(aeskey, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(aeskey, AES.MODE_ECB)
    plaintext_with_padding = cipher.decrypt(ciphertext).decode()
    padding_length = ord(plaintext_with_padding[-1])
    plaintext = plaintext_with_padding[:-padding_length]
    return plaintext

def to_ug_datetime(date_time):
    ug_time_zone = "Africa/Kampala"
    uganda_time = date_time.astimezone(pytz.timezone(ug_time_zone))
    uganda_time_str = uganda_time.strftime("%Y-%m-%d %H:%M:%S")
    return uganda_time_str

def get_ug_time_str():
    ug_time_zone = "Africa/Kampala"
    now = datetime.now()
    uganda_time = now.astimezone(pytz.timezone(ug_time_zone))
    uganda_time_str = uganda_time.strftime("%Y-%m-%d %H:%M:%S")
    return uganda_time_str

def fetch_data():
    now = get_ug_time_str()
    return {
        "data": {
            "content": "",
            "signature": "",
            "dataDescription": {
                "codeType": "0",
                "encryptCode": "1",
                "zipCode": "0"
            }
        },
        "globalInfo": {
            "appId": "AP04",
            "version": "1.1.20191201",
            "dataExchangeId": "9230489223014123",
            "interfaceCode": "T101",
            "requestTime": now,
            "requestCode": "TP",
            "responseCode": "TA",
            "userName": "admin",
            "deviceMAC": "FFFFFFFFFFFF",
            "deviceNo": "1017460267_01",
            "tin": "1017460267",
            "brn": "",
            "taxpayerID": "1",
            "longitude": "116.397128",
            "latitude": "39.916527",
            "extendField": {
                "responseDateFormat": "dd/MM/yyyy",
                "responseTimeFormat": "dd/MM/yyyy HH:mm:ss"
            }
        },
        "returnStateInfo": {
            "returnCode": "",
            "returnMessage": ""
        }
    }

def get_AES_key():
    try:
        data = fetch_data()
        efris_log_info("Data fetched successfully - inside get_AES_key")

        deviceNo = "1017460267_01"
        tin = "1017460267"
        brn = ""
        dataExchangeId = guidv4()

        data["globalInfo"]["interfaceCode"] = "T104"
        data["globalInfo"]["dataExchangeId"] = dataExchangeId
        data["globalInfo"]["deviceNo"] = deviceNo
        data["globalInfo"]["tin"] = tin
        data["globalInfo"]["brn"] = brn

        data_json = json.dumps(data).replace("'", '"').replace("\n", "").replace("\r", "")
        efris_log_info("Request data converted to JSON successfully")

        resp = post_req(data_json)
        efris_log_info("POST request to fetch AES key successful")

        jsonresp = json.loads(resp)
        efris_log_info("Response JSON parsed successfully")

        b64content = jsonresp["data"]["content"]
        content = json.loads(base64.b64decode(b64content).decode("utf-8"))
        efris_log_info("Content extracted from response")

        b64passwordDes = content["passowrdDes"]
        passwordDes = base64.b64decode(b64passwordDes)
        efris_log_info("PasswordDes decoded successfully")

        privKey = get_private_key()
        efris_log_info("Private key fetched successfully")

        # Convert the private key to a PEM format byte string for RSA import
        pkey_str = privKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        efris_log_info("pkey_str converted...")

        # Decrypt AES key using the private key
        cipher = PKCS1_v1_5.new(RSA.import_key(pkey_str))
        aesKey = cipher.decrypt(passwordDes, None)

        efris_log_info("AES key decrypted successfully")
        return base64.b64decode(aesKey)

    except Exception as e:
        efris_log_error("An error occurred in get_AES_key(): " + str(e))
        return None

def guidv4():
    my_uuid = uuid.uuid4()
    my_uuid_str = str(my_uuid)
    my_uuid_str_32 = my_uuid_str.replace("-", "")
    return my_uuid_str_32

def post_req(data):
    efris_log_info("post_req()...starting")
    url = "https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, data=data, headers=headers)
    print(response.text)
    efris_log_info("post_req()...done, response:" + response.text)
    return response.text

def post_reqs(data, url, headers):
    efris_log_info("post_req()...")
    response = requests.post(url, data=data, headers=headers)
    print(response.text)
    return response.text

def get_private_key():
    try:
        efris_log_info("get_private_key() starts...")
        
        key_file_path = "key/online_mode_pk.p12"
        with open(key_file_path, "rb") as f:
            pfx_data = f.read()
            efris_log_info("read the key...")

        pfx = pkcs12.load_key_and_certificates(pfx_data, b"efris", default_backend())
        efris_log_info("pfx done...")

        private_key = pfx[0]  # The private key is the first element

        if private_key is None:
            efris_log_info('Private key extraction failed: private_key is None')
            return None
        
        efris_log_info("get_private_key()...done")
        return private_key
    except Exception as e:
        efris_log_error(f'Error extracting private key: {e}')
        return None

def sign_data(private_key, data):
    try:
        # Use the private key to sign the data
        signature = private_key.sign(
            data,
            asym_padding.PKCS1v15(),
            hashes.SHA1()
        )

        efris_log_info("Data signed successfully")
        return signature
    except Exception as e:
        efris_log_error(f'Error signing data: {e}')
        return None

def safe_load_json(message):
    try:
        json_message = json.loads(message)
    except Exception:
        json_message = message

    return json_message

def format_amount(amount):
    amt_float = float(amount)    
    amt_string = "{:.2f}"
    return amt_string.format(amt_float)

if __name__ == "__main__":
    main()
