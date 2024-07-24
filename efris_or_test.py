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
    # resp_content = make_post("T130", goodsUpload)
    # resp_content = make_post("T130", serviceUpload)
    # resp_content = make_post("T109", invoiceUpload_Goods_Ezzy)
    # resp_content = make_post("T130", invoiceUpload_Goods_NonExcise)
    resp_content = make_post("T131", Goods_stock_adjustment_T131)
    logging.info(f"Main response: {resp_content}")

random_integer = random.randint(1, 1000000)

goodsUpload = [
    {
        "operationType": "101",
        "goodsName": "pencils-231",
        "goodsCode": "0008598986",
        "measureUnit": "101",
        "unitPrice": "12000",
        "currency": "101",
        "commodityCategoryId": "50151513",
        "haveExciseTax": "102",
        "stockPrewarning": "0",
        "havePieceUnit": "102",
        "goodsOtherUnits": [],
    }
]

serviceUpload = [
    {
        "operationType": "101",
        "goodsName": "Professional Fees 3",
        "goodsCode": "Professional Fees 3",
        "measureUnit": "101",
        "unitPrice": "1500000",
        "currency": "101",
        "commodityCategoryId": "80101512",
        "haveExciseTax": "102",
        "stockPrewarning": "0",
        "havePieceUnit": "102",
        "goodsOtherUnits": [],
    }
]
invoiceUpload_Goods_Ezzy = {
    
    "airlineGoodsDetails": [],
    "basicInformation": {
         "invoiceNo": "",
      "antifakeCode": "",
      "deviceNo": "1017460267_01",
      "issuedDate": "2023-07-18",
      "operator": "Administrator",
      "currency": "UGX",
      "oriInvoiceId": "1",
      "invoiceType": "1",
      "invoiceKind": "1",
      "dataSource": "101",
      "invoiceIndustryCode": "101",
      "isBatch": "0"
    },
    "buyerDetails": {
        "buyerAddress": " BANANUKA STREET NEAR  INTERNATIONAL WINDOW GIRLS SCHOOL MBARARA CITY MBARARA MBARARA MUNICIPALITY NYAMITANGA KATETE ",
        "buyerBusinessName": "RKC  ENTERPRISES LIMITED",
        "buyerEmail": "kamukamadavid01@gmail.com",
        "buyerLegalName": "RKC  ENTERPRISES LIMITED",
        "buyerLinePhone": "2560778497936",
        "buyerNinBrn": "/80020003074811",
        "buyerSector": "Telecommunications Industry",
        "buyerTin": "1018311347",
        "buyerType": "0"
       },
    "extend": {},
    "goodsDetails":{
        "deemedFlag": "2",
        "discountFlag": "2",
        "exciseFlag": "2",
        "exciseTax": "",
        "goodsCategoryId": "14111601",
        "goodsCategoryName": "Gift wrapping paper or bags or boxes",
        "item": "AZHAR LASER 070G A4 5RM PACK",
        "itemCode": "14111601",
        "orderNumber": "0",
        "pack": "1",
        "qty": "10",
        "stick": "1",
        "tax": "99483.56",
        "taxRate": "0.18",
        "total": "652170.00",
        "unitOfMeasure": "SW",
        "unitPrice": "65217",
        "vatApplicableFlag": "1",
		"discountTotal":"",
        "discountTaxRate": "0.00",
        "categoryId": "",
        "categoryName": "",
        "exciseRate": "",
        "exciseRule": "",
        "exciseUnit": "101",
        "exciseCurrency": "UGX",
        "exciseRateName": "",
        "deemedExemptCode": "",
        "vatProjectId": "",
        "vatProjectName": ""
    }
    ,
    "payWay": [
        {
         "paymentMode": "101",
         "paymentAmount": "652170.00",
         "orderNumber": "a",
         "nowTime":""
      }        
        ],
    "sellerDetails": {
        "address": "109 OLD PORTBELL ROAD AKAMWESI HOUSE KATAZA KAMPALA NAKAWA DIVISION NAKAWA DIVISION  ",
        "branchCode": "00",
        "branchId": "799150987600117988",
        "branchName": "SKY MASTER EXPRESS LIMITED",
        "businessName": "EZZI GROUP COMPANY LIMITED",
        "emailAddress": "aliasger.ezzi@ezzi-group.com",
        "legalName": "EZZI GROUP COMPANY LIMITED",
        "linePhone": "00256",
        "mobilePhone": "2560778497936",
        "ninBrn": "/106289",
        "placeOfBusiness": "109 OLD PORTBELL ROAD AKAMWESI HOUSE KATAZA KAMPALA NAKAWA DIVISION NAKAWA DIVISION  ",
        "referenceNo": "Test Ref 12345",
        "tin": "1017460267",
		"referenceNo": str(random_integer),
        "isCheckReferenceNo": "0",
		
    },
    "summary": {
        "taxAmount": "99483.56",
        "grossAmount": "652170.00",
        "itemCount": "1",
        "netAmount": "552686.44",
        "modeCode": "1",         
        "qrCode": "",
        "remarks": "Test Ezzy invoice."
    },
    "taxDetails": 
       {
         "taxCategoryCode": "01",
         "netAmount": "552686.44",
         "taxRate": "0.18",
         "taxAmount": "99483.56",
         "grossAmount": "652170.00",
         "exciseUnit": "101",
         "exciseCurrency": "UGX",
         "taxRateName": "123"
      }
        
}
invoiceUpload_Goods_NonExcise = {
   "sellerDetails": {
      "tin": "1002170340",
      "ninBrn": "",
      "legalName": "ASK CORPORATE CONSULTS LTD",
      "businessName": "ASK CORPORATE CONSULTS LTD",
      "address": "KAMPALA",
      "mobilePhone": "15501234567",
      "linePhone": "010-6689666",
      "emailAddress": "123456@163.com",
      "placeOfBusiness": "1496 KYEBANDO ROAD BUSINESS GARDEN KAMWOKYA KAMPALA KAWEMPE DIVISION SOUTH KAWEMPE DIVISION MULAGO III",
      "referenceNo": str(random_integer),
      "branchId": "",
      "isCheckReferenceNo": "0",
      "branchName": "Test",
      "branchCode": ""
   },
   "basicInformation": {
      "invoiceNo": "",
      "antifakeCode": "",
      "deviceNo": "1002170340_01",
      "issuedDate": "2023-06-14",
      "operator": "Administrator",
      "currency": "UGX",
      "oriInvoiceId": "1",
      "invoiceType": "1",
      "invoiceKind": "1",
      "dataSource": "101",
      "invoiceIndustryCode": "101",
      "isBatch": "0"
   },
   "buyerDetails": {
      "buyerTin": "1016851411",
      "buyerNinBrn": "/80020002454894",
      "buyerPassportNum": "",
      "buyerLegalName": "TECH THINGS LIMITED",
      "buyerBusinessName": "TECH THINGS LIMITED",
      "buyerAddress": "beijin",
      "buyerEmail": "123456@163.com",
      "buyerMobilePhone": "15501234567",
      "buyerLinePhone": "010-6689666",
      "buyerPlaceOfBusi": "beijin",
      "buyerType": "0",
      "buyerCitizenship": "1",
      "buyerSector": "1",
      "buyerReferenceNo": "00000000001",
      "nonResidentFlag": "0"
   },
   "buyerExtend": {
      "propertyType": "abc",
      "district": "haidian",
      "municipalityCounty": "haidian",
      "divisionSubcounty": "haidian1",
      "town": "haidian1",
      "cellVillage": "haidian1",
      "effectiveRegistrationDate": "2020-10-19",
      "meterStatus": "101"
   },
   "goodsDetails": [
      {
         "item": "pencils-10",
         "itemCode": "0008396770",
         "qty": 20,
         "unitOfMeasure": "101",
         "unitPrice": "12000.00",
         "total": "240000.00",
         "taxRate": "0.18",
         "tax": "36610.17",
         "discountTotal": "",
         "discountTaxRate": "0.00",
         "orderNumber": 0,
         "discountFlag": "2",
         "deemedFlag": "2",
         "exciseFlag": "2",
         "categoryId": "",
         "categoryName": "",
         "goodsCategoryId": "50151513",
         "goodsCategoryName": "Edible vegetable or plant oils",
         "exciseRate": "",
         "exciseRule": "",
         "exciseTax": "",
         "pack": "",
         "stick": "",
         "exciseUnit": "101",
         "exciseCurrency": "UGX",
         "exciseRateName": "",
         "vatApplicableFlag": "1",
         "deemedExemptCode": "",
         "vatProjectId": "",
         "vatProjectName": "testAskcc"
      }
   ],
   "taxDetails": [
      {
         "taxCategoryCode": "01",
         "netAmount": "203389.83",
         "taxRate": "0.18",
         "taxAmount": "36610.17",
         "grossAmount": "240000.00",
         "exciseUnit": "101",
         "exciseCurrency": "UGX",
         "taxRateName": "123"
      }
   ],
   "summary": {
      "netAmount": "203389.83",
      "taxAmount": "36610.17",
      "grossAmount": "240000.00",
      "itemCount": 1,
      "modeCode": "0",
      "remarks": "Test Askcc invoice.",
      "qrCode": ""
   },
   "payWay": [
      {
         "paymentMode": "101",
         "paymentAmount": "240000.00",
         "orderNumber": "a"
      }
   ],
   "extend": {
      "reason": "",
      "reasonCode": ""
   },
   "importServicesSeller": {
      "importBusinessName": "",
      "importEmailAddress": "",
      "importContactNumber": "",
      "importAddress": "",
      "importInvoiceDate": "2023-05-21",
      "importAttachmentName": "",
      "importAttachmentContent": ""
   },
   "airlineGoodsDetails": [
      {
         "item": "pencils-10",
         "itemCode": "0008396770",
         "qty": "20",
         "unitOfMeasure": "101",
         "unitPrice": "12000.00",
         "total": "240000.00",
         "taxRate": "0.18",
         "tax": "36610.17",
         "discountTotal": "",
         "discountTaxRate": "0.00",
         "orderNumber": "1",
         "discountFlag": "2",
         "deemedFlag": "1",
         "exciseFlag": "2",
         "categoryId": "",
         "categoryName": "",
         "goodsCategoryId": "50151513",
         "goodsCategoryName": "Edible vegetable or plant oils",
         "exciseRate": "",
         "exciseRule": "",
         "exciseTax": "",
         "pack": "",
         "stick": "",
         "exciseUnit": "101",
         "exciseCurrency": "UGX",
         "exciseRateName": ""
      }
   ],
   "edcDetails": {
      "tankNo": "1111",
      "pumpNo": "2222",
      "nozzleNo": "3333",
      "controllerNo": "",
      "acquisitionEquipmentNo": "",
      "levelGaugeNo": "",
      "mvrn": "",
      "updateTimes": ""
   },
   "agentEntity": {
      "tin": "",
      "legalName": "",
      "businessName": "",
      "address": ""
   }
}
Goods_stock_adjustment_T131= {
"goodsStockIn": {
"operationType": "101",
"supplierTin": "",
"supplierName": "Test",
"adjustType": "",
"remarks": "Increase inventory",
"stockInDate": "2024-07-18",
"stockInType": "101",
"productionBatchNo": "",
"productionDate": "",
"branchId": "799150987600117988",
"invoiceNo": "00000011",
"isCheckBatchNo": "0",
"rollBackIfError": "0",
"goodsTypeCode": "101"
},
"goodsStockInItem": [{
"commodityGoodsId": "255738155268950014",
"goodsCode": "14111601",
"measureUnit": "101",
"quantity": "50",
"unitPrice": "46000",
"remarks": "remarks",
"fuelTankId": "568654903587001037",
"lossQuantity": "10",
"originalQuantity": "110"
}]
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
