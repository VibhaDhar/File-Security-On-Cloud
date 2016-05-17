'''Copyright (c) 2015 HG,DL,UTA
   Python program runs on local host, uploads, downloads, encrypts local files to google.
   Please use python 2.7.X, pycrypto 2.6.1 and Google Cloud python module '''

import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
import csv
#Google apliclient (Google App Engine specific) libraries.
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from apiclient.http import MediaIoBaseDownload
from apiclient.http import MediaFileUpload
#pycry#pto libraries.
from Crypto import Random
from Crypto.Cipher import AES



def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(message, key, key_size=256):
    message = pad(message)
    #iv is the initialization vector
    iv = Random.new().read(AES.block_size)
    #encrypt entire message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name, 'wb') as fo:
        fo.write(enc)


def decrypt_file(ciphertext, key,file_name):
    dec = decrypt(ciphertext, key)
    with open(file_name, 'wb') as fo:
        fo.write(dec)



_BUCKET_NAME = '' #name of your google bucket.
_API_VERSION = 'v1'
D={}

parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])


CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')

FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
      'https://www.googleapis.com/auth/devstorage.read_write',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))
key="test"

def get(service):

  try:

    file_name = raw_input('Which filename to download from cloud?\n')
    req = service.objects().get(bucket=_BUCKET_NAME,object=file_name,)
    resp = req.execute()
    print json.dumps(resp, indent=2)


    req = service.objects().get_media(bucket=_BUCKET_NAME,object=file_name,)    
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req, chunksize=1024*1024)
    done = False
    while not done:
            status, done = downloader.next_chunk()
            if status:
               	 print 'Download %d%%.' % int(status.progress() * 100)
    print 'Download Complete!'
    reader = csv.reader(open('dict_pw.csv', 'rb'))
    newD = dict(x for x in reader)     
    key= newD[file_name]
    print key
    decrypt_file(fh.getvalue(),key,file_name)



  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

 
def put(service): 

    input_file = raw_input('Give the file name to store on cloud: \n')

    #Initial password to create a key
    password = raw_input('Input a password for encrypting the file:\n')
    #key to use
    key = hashlib.sha256(password).digest()
    print key
    encrypt_file(input_file,key)
    D[input_file]=key
    writer = csv.writer(open('dict_pw.csv', 'wb'))
    for key, value in D.items():
        writer.writerow([key, value])
    media = MediaFileUpload(input_file, mimetype='application/octet-stream')
    req = service.objects().insert(
        bucket=_BUCKET_NAME,
        name=input_file,
        media_body=media)
    resp = req.execute()
    print json.dumps(resp, indent=2)
    os.remove(input_file)


#Lists all the objects from the given bucket name
def listobj(service):
    req = service.objects().list(
            bucket=_BUCKET_NAME
            )

    while req is not None:
        resp = req.execute()
        resp_str =  json.dumps(resp, indent=2)
        resp_json = json.loads(resp_str)
        for items in resp_json['items']:
            print items['name']       
        req = service.objects().list_next(req, resp)
       

#This deletes the object from the bucket
def deleteobj(service):
    '''Prompt the user to enter the name of the object to be deleted from your bucket.
        Pass the object name to the delete() method to remove the object from your bucket'''
    delete_file  = raw_input('Enter the file name to be deleted : \n')
    service.objects().delete(
        bucket=_BUCKET_NAME,
        object=delete_file).execute()

   
def main(argv):  
  flags = parser.parse_args(argv[1:])
  storage = file.Storage('sample.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)
  http = httplib2.Http()
  http = credentials.authorize(http)
  service = discovery.build('storage', _API_VERSION, http=http)
  options = {1: put, 2: get, 3:listobj, 4:deleteobj}
  exit = 0 
  while exit != 1:
      option = int(raw_input('Choose 1.Put a file to cloud 2.Get a file from cloud 3.LIst the files in cloud 4.Delete the file in the cloud \n'))
      if option == 5:
        exit = 1
      else:
        options[option](service)
      print '\n\n'
if __name__ == '__main__':
  main(sys.argv)
# [END all]

