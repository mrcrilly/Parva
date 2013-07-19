#!/usr/bin/env python

'''
tpm.py - Tiny Password Manager
'''

# Script information
__author__					= "Michael Crilly"
__copyright__				= "Public domain"
__license__					= "Public Domain"
__version__					= "0.0.5"

from getpass import getpass, getuser
from pwgen import pwgen
from datetime import datetime,timedelta
from os.path import exists, getsize
from os import remove
from shutil import copy2
from time import sleep

# Cryptographic functions
from Crypto.Cipher import AES
from Crypto import Random
from pbkdf2 import PBKDF2

import json

# Database - we use a flat file
DB_DATA_FILE				= './safe'
SKEY_SALT					= 'Iex5Eiqueizaba5moS9es1wo3eethii3oniw7igh5eitie0olo'

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
		fd = open(DB_DATA_FILE, 'w')
		fd.close()

	return structure

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
	Note that we simply overwrite the existing backup.
	'''
	backup = "{}.backup".format(DB_DATA_FILE)

	if exists(DB_DATA_FILE):
		copy2(DB_DATA_FILE, backup)

def printJSON(print_me):
	'''
	Central point for defining pretty JSON printing
	'''
	print json.dumps(print_me, separators=(':', ','), sort_keys=True, indent=4)

def addRecord(db, tag, username=None, system=None, sensitivity=None, enabled=True, readOnly=False):
	'''
	Add a new record to the database
	'''
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
			r'username': username,
			r'system': system,
			r'sensitivity': sensitivity,
			r'enabled': enabled,
			r'read_only': readOnly,
	}

	db['secrets'][tag] = entry
	return db

def editRecord(db, tag, attribute, newValue):
	'''
	Edit the given tag, updating the attribute with the new value
	'''
	if tag in db['secrets']:
		if db['secrets'][tag]['read_only'] == 1 and not attribute == "read_only":
			print "This record is read-only. Turn this flag off first."
			exit(1)
		db['secrets'][tag][attribute] = newValue
		return db
	else:
		print "Unable to find that tag in the database."
		exit(1)

def viewRecord(db, tag):
	'''
	Match the string and display the results
	'''
	if tag in db['secrets']:
		dumpRecords(db['secrets'][tag], compact=False)
	else:
		print "Unable to find that tag in the database."
		exit(1)

def viewPassword(db, tag):
	'''
	Print out only the password.
	'''
	if tag in db['secrets']:
		pw = db['secrets'][tag]['password']
		print "Password: {}".format(pw)
	else:
		print "Unable to find that tag in the database."
		exit(1)

def deleteRecord(db, tag):
	'''
	Delete an existing record from the database.

	Needs work!!
	'''
	if tag in db['secrets']:
		if db['secrets'][tag]['read_only'] == 1:
			print "This record is read-only. It can't be deleted."
			exit(1)

		del db['secrets'][tag]
		return db
	else:
		print "Unable to find that tag in the database."
		exit(1)

def dumpRecords(data, compact=False):
	'''
	Dump all of the records into a compact JSON format.
	'''
	if not compact:
		print json.dumps(data, separators=(',', ':'), sort_keys=True, indent=4)
	else:
		print json.dumps(data)

def encryptDatabase(secretkey, data):
	'''
	Utilise the Crypto library and implement AES-256-CFB encryption to the database.
	We don't use temporary files here - everything is kept in variables and therefore memory (we hope).
	'''
	IV = Random.new().read(16)
	engine = AES.new(secretkey, AES.MODE_CFB, IV)

	if exists(DB_DATA_FILE):
		fd = open(DB_DATA_FILE, 'wb')
		if fd:
			jdata = json.JSONEncoder().encode(data)
			fd.write(IV + engine.encrypt(jdata))
			fd.close()
		else:
			print "Problem opening database."
			exit(1)
	else:
		print "Unable to find database file."
	
def decryptDatabase(secretkey):
	'''
	Decrypt the database. We utilise AES-256-CFB mode.
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

	return json.JSONDecoder().decode(denc_data)

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
	ap.add_argument('-a', '--add', metavar='tag', dest='add', help='Add a new record, auto-generating a password')
	ap.add_argument('-d', '--delete', metavar='tag', dest='delete', help='Delete the given tag')
	ap.add_argument('-e', '--edit', metavar='tag', dest='edit', help='Edit the given tag')
	ap.add_argument('-v', '--view', metavar='tag', dest='view', help='View an individual record/tag')
	ap.add_argument('-p', '--password', metavar='tag', dest='password', help='View only the password for a given tag')

# Optionals to the above
	ap.add_argument('-U', metavar='username', dest='username', help='Username for the given tag')
	ap.add_argument('-S', metavar='system', dest='system', help='System for the given tag, such as an IP or hostname/URL')
	ap.add_argument('-Z', metavar='sensitivity', dest='sensitivity', help='Define how sensitive this password is. 0=confidential; 1=classified; 2=secret; 3=top-secret', type=int)
	ap.add_argument('-E', metavar='enabled', dest='enabled', help='Enable or disable the tag. Disabling excludes it from output and wanrs when viewed', type=int)
	ap.add_argument('-R', metavar='readonly', dest='readonly', help='Set the entry as read-only. This prevents editing', type=int)

# Database policy options
	ap.add_argument('--policy', dest='policy', help='Display the database policies', action='store_true')
	ap.add_argument('--policy-pw-length', metavar='len', dest='pwlen', help='Update the policy password length', type=int)
	ap.add_argument('--policy-no-symbols', dest='symbols', help='Turn off symbols in passwords', action='store_true')
	ap.add_argument('--policy-expires', metavar='days', dest='expires', help='Set the number of days the password expires', type=int)
	ap.add_argument('--policy-auto-renew', dest='autorenew', help='Turn on or off auto password refresh.', action='store_true')

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
		data = createDatabase()
		encryptDatabase(skey, data)

# Policy editing
	if args.policy:
		data = decryptDatabase(skey)
		dumpRecords(data['policy'])

	if args.pwlen:
		data = decryptDatabase(skey)
		data['policy']['password_length'] = args.pwlen
		encryptDatabase(skey, data)

	if args.symbols:
		data = decryptDatabase(skey)
		if data['policy']['no_symbols']:
			data['policy']['no_symbols'] = False
		else:
			data['policy']['no_symbols'] = True
		encryptDatabase(skey, data)

	if args.expires:
		data = decryptDatabase(skey)
		data['policy']['expires_in'] = args.expires
		encryptDatabase(skey, data)

	if args.autorenew:
		data = decryptDatabase(skey)
		if data['policy']['auto_renew']:
			data['policy']['auto_renew'] = False
		else:
			data['policy']['auto_renew'] = True
		encryptDatabase(skey, data)

# ADD RECORD
	if args.add:
		data = decryptDatabase(skey)
		data = addRecord(data, args.add)

		if args.username:
			data['secrets'][args.add]['username'] = args.username
		if args.system:
			data['secrets'][args.add]['system'] = args.system
		if args.sensitivity:
			if int(args.sensitivity) < 0 or int(args.sensitivity) > 3:
				print "Sensitivity values supported: 0, 1, 2 and 3."
				exit(1)
			else:
				data['secrets'][args.add]['sensitivity'] = int(args.sensitivity)
		if args.enabled:
			if int(args.enabled) < 0 or int(args.enabled) > 1:
				print "Enabled flag requires 0 (zero/disabled) or 1 (one/enabled - default)"
				exit(1)
			else:
				data['secrets'][args.add]['enabled'] = int(args.enabled)
		if args.readonly:
			if int(args.readonly) < 0 or int(args.readonly) > 1:
				print "Read-only flags requires 0 (zero/false - default) or 1 (one/true)"
				exit(1)
			else:
				data['secrets'][args.add]['read_only'] = int(args.readonly)

		encryptDatabase(skey, data)

# DELETE RECORD
	if args.delete:
		data = decryptDatabase(skey)
		data = deleteRecord(data, args.delete)
		encryptDatabase(skey, data)

# EDIT RECORD
	if args.edit:
		data = decryptDatabase(skey)
		if args.username:
			editRecord(data, args.edit, 'username', args.username)
		elif args.system:
			editRecord(data, args.edit, 'system', args.system)
		elif args.sensitivity:
			editRecord(data, args.edit, 'sensitivity', args.sensitivity)
		elif args.enabled:
			editRecord(data, args.edit, 'enabled', args.enabled)
		elif args.readonly:
			editRecord(data, args.edit, 'read_only', args.readonly)
		else:
			print "No attribute given."
			exit(1)

		encryptDatabase(skey, data)
	
# VIEW RECORD
	if args.view:
		data = decryptDatabase(skey)
		viewRecord(data, args.view)

# VIEW PASSWORD
	if args.password:
		data = decryptDatabase(skey)
		viewPassword(data, args.password)	

# PRINT UGLY JSON
	if args.json:
		data = decryptDatabase(skey)
		dumpRecords(data, True)
		exit(0)

# PRINT PRETTY JSON
	if args.pjson:
		data = decryptDatabase(skey)
		dumpRecords(data, False)
		exit(0)

if __name__ == "__main__":
	main()