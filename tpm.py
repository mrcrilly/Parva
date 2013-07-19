#!/usr/bin/env python

'''
tpm.py - Tiny Password Manager
'''

# Script information
__author__					= "Michael Crilly"
__copyright__				= "Public domain"
__credits__					= [ "Python developers",  "Linus Tarvolds", "The NSA" ]
__license__					= "Public Domain"
__version__					= "0.0.2"

from getpass import getpass, getuser
from pwgen import pwgen
from datetime import datetime,timedelta
from os.path import exists, getsize
from os import remove
from shutil import copy2
from time import sleep

# Cryptographic functions
from Crypto.Cipher import AES
from Cyrpto import Random
from pbkdf2 import PBKDF2

import json

# Database - we use a flat file
DB_DATA_FILE				= './safe'
SKEY_SALT					= 'Iex5Eiqueizaba5moS9es1wo3eethii3oniw7igh5eitie0olo'

# 2013-07-18 - This should not be needed; mc
#(DB_TMP_FD, TMP_DATA_FILE) 	= mkstemp(dir='/dev/shm')

def createDatabase():
	'''
	Create a new empty database with the default structure.
	'''
	structure = {
		r'secrets': {},
		r'policy': {
			r'revision': 0,
			r'password_length': 50,
			r'no_symbols': False,
			r'expires_in': 90,
			r'auto_renew': True
		},
		r'created': str(datetime.now()),
		r'modified': None,
		r'accessed': None
	}

	if not exists(DB_DATA_FILE):
		fd = open(TMP_DATA_FILE, 'w')
		if fd:
			fd.write(r"{}".format(json.JSONEncoder().encode(structure)))
			fd.close()
		else:
			print "Unable to create new database. Exiting."
			exit(1)
	else:
		print "Please move or delete the existing database."

def openDatabase():
	'''
	Open up the database, pulling in the JSON data for manipulation.
	'''
	if exists(DB_DATA_FILE):
		fd = open(DB_DATA_FILE, 'rb')
		if fd:
			return(json.JSONDecoder().decode(fd.read()))
			fd.close()
		else:
			print "Problem opening database file."
			exit(1)
	else:
		print "Database file doesn't exist."
		exit(1)

def backupDatabase():
	'''
	Create a backup of the database. This is done before any manipulation to the database.
	'''
	backup = "{}.backup".format(DB_DATA_FILE)

	if os.path.exists(DB_DATA_FILE):
		if os.path.exists(backup):
			shredRemains(backup)

		copy2(DB_DATA_FILE, backup)

def printJSON(print_me):
	'''
	Central point for defining pretty JSON printing
	'''
	print json.dumps(print_me, separators=(':', ','), sort_keys=True, indent=4)

def addRecord(tag):
	'''
	Add a new record to the database
	'''
	db = openDatabase()

# Tags need to be unique
	if tag in db['secrets']:
		print "Tags need to be unique."
		exit(1)

# Define the new entry.
	entry = {
			r'password': pwgen(db['policy']['password_length'], no_symbols=db['policy']['no_symbols']),
			r'expires': str(datetime.now() + timedelta(days=+(db['policy']['expires_in']))),
			r'added': str(datetime.now()),
			r'modified': None,
			r'accessed': None,
# Currently unused elements - for future use
			r'username': None,
			r'system': None,
			r'sensitivity': None,
			r'enabled': None,
			r'read_only': None,
	}

	db['secrets'][tag] = entry

	fd = open(TMP_DATA_FILE, 'w')
	if fd:
		fd.write(r"{}".format(json.JSONEncoder().encode(db)))
		fd.close()
	else:
		print "Problem opening database file."
		exit(1)

def viewRecord(tag):
	'''
	Match the string and display the results
	'''
	db = openDatabase()

	if tag in db['secrets']:
		printJSON(db['secrets'][tag])
	else:
		print "Unable to find that tag in the database."
		exit(1)

def deleteRecord(tag):
	'''
	Delete an existing record from the database.

	Needs work!!
	'''
	pass

def dumpRecords(data):
	'''
	Dump all of the records into a compact JSON format.
	'''
	print json.dumps(data, separators=(',', ':'), sort_keys=True, indent=4)

def encryptDatabase(secretkeyi, data):
	'''
	Issue an OpenSSL command to encrypt database.
	'''
	IV = Random.new().read(16)
	engine = AES.new(secretkey, AES.MODE_CFB, IV)

	if exists(DB_DATA_FILE):
		fd = open(DB_DATA_FILE, 'wb')
		if fd:
			fd.write(IV + engine.encrypt(data))
			fd.close()
		else:
			print "Problem opening database."
			exit(1)
	else:
		print "Unable to find database file."
	
def decryptDatabase(secretkey):
	'''
	Issue an OpenSSL command to decrypt the database.
	'''
	if exists(DB_DATA_FILE):
		fd = open(DB_DATA_FILE, 'rb')
		if fd:
			IV = fd.read(16)
			data = fd.read()
			engine = AES.new(secretkey, AES.MODE_CFB, IV)
			denc_data = engine.decrypt(data)
			fd.close()
		else:
			print "Unable to open database file."
			exit(1)
	else:
		print "Unable to find database file."
		exit(1)

	return denc_data

def main():
	'''
	Our application entry point.
	'''

# Set up and handle argument parsing
	from argparse import ArgumentParser
	ap = ArgumentParser()

# Database options
	ap.add_argument('-c', '--create-database', dest='create', help='Create a new database', action='store_true')

# Database record handling options
	ap.add_argument('-a', '--add', metavar='tag', dest='add', help='Add a new record')
	ap.add_argument('-d', '--delete', metavar='tag', dest='delete', help='Delete an existing record')
	ap.add_argument('-e', '--edit', dest='edit', help='Edit the database', action='store_true')
	ap.add_argument('-v', '--view', metavar='tag', dest='view', help='View an individual record')

# Database record exporting
	ap.add_argument('-j', '--compact-json', dest='json', help='Dump the database: compact and ugly.', action='store_true')
	ap.add_argument('-J', '--pretty-json', dest='pjson', help='Dump the database: verbose and pretty.', action='store_true')

# Encryption and Decryption flags
	ap.add_argument('--encrypt', dest='encrypt', help='Encrypt the database', action='store_true')
	ap.add_argument('--decrypt', dest='decrypt', help="Decrypt the database (risky)", action='store_true')
	ap.add_argument('-k', '--key', dest='key', help='The secret key')

	args = ap.parse_args()

# If we're not passed the key via -k/--key, ask for the password
	if not args.key:
		skey_1 = getpass("Secret Key: ")
		skey_2 = getpass("Secret Key (again): ")
		
		if not skey_1 == skey_2:
			print "The secret keys don't match."
			exit(1)
		else:
			skey = PBKDF2(skey_1, SKEY_SALT).read(32)		
	else:
		skey = PBKDF2(args.key, SKEY_SALT).read(32)

# Check the database exists before trying to do anything else
	if not exists(DB_DATA_FILE) or args.create:
		createDatabase()
		fd = open(DB_DATA_FILE, 'rb')
		data = fd.read()
		fd.close()
		encryptDatabase(skey, data)

# ENCRYPT
	if args.encrypt:
#		backupDatabase()
		fd = open(DB_DATA_FILE, 'rb')
		data = fd.read()
		fd.close()
		encryptDatabase(secret_key, data)
		exit(0)

# DECRYPT
#	if args.decrypt:
#		backupDatabase()
#		decryptDatabase(secret_key, db_to='./unsafe')
#		exit(0)

# ADD RECORD
	if args.add:
		exit(0)

# DELETE RECORD
	if args.delete:
		exit(0)

# EDIT RECORD
	if args.edit:
		print "Edit the database"
		exit(0)

# PRINT UGLY JSON
	if args.json:
		data = decryptDatabase(skey)
		dumpRecords(data)
		exit(0)

# PRINT PRETTY JSON
	if args.pjson:
		pass

# PRINT RECORD
	if args.view:
		exit(0)

if __name__ == "__main__":
	main()
