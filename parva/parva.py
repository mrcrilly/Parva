#!/usr/bin/env python

'''
Script:			parva.py
Application:	Parva
Description:	Parva is a small, light weight, CLI based password manager.
URL:			https://github.com/mrcrilly/Parva
Author:			Michael Crilly
Contact:		mrcrilly@gmail.com
'''

# Script information
__author__ = "Michael Crilly <mrcrilly@gmail.com>"
__copyright__ = "Not defined"
__license__	= "Not defined"
__version__	= "1.0.8"

from getpass import getpass
from pwgen import pwgen
from datetime import datetime, timedelta
from os.path import exists
from shutil import copy2, move
from time import sleep

# Cryptographic functions
from Crypto.Cipher import AES
from Crypto import Random
from pbkdf2 import PBKDF2

import json

REMOTE_VAULT = False
THE_VAULT = 'vault'

SKEY_SALT = "vr]rN&o|'O@`3leIUm/K7%W+id^.vd~K,&G?AqBI#g1ov>L:sn:\:]VdQd{lMl'W<p(FEVTOI{n+rV$h6Q|_H+\ERH&s+|Wc[=?;"

def createDatabase():
	'''
	Creates an empty JSON database (unencrypted). This defines the default database structure.
	
	Arguments: None
	Returns: JSON structure
	'''
	structure = {
		r'secrets': {},
		r'policy': {
			r'password_length': 50,
			r'no_symbols': False,
			r'expires_in': 90,
		},
		r'created': str(datetime.now().isoformat()),
		r'client_version': __version__,
	}

	if not exists(THE_VAULT):
		fd = open(THE_VAULT, 'w')
		fd.close()
			
	return structure

def backupDatabase():
	'''
	Create a backup of the database. This is done before any manipulation to the database.
	Note that we simply overwrite the existing backup.
	'''
	if exists(THE_VAULT):
		copy2(THE_VAULT, "{0}.backup".format(THE_VAULT))

def generatePassword(policy):
	'''
	General purpose password generator. Uses the policy to generate passwords.
	'''
	return pwgen(policy['password_length'], no_symbols=policy['no_symbols'])

def addRecord(db, tag, username=None, system=None, sensitivity=None, enabled=True, readOnly=False):
	'''
	Add a new record to the database by generating a JSON object and injecting it.
	'''
	if tag in db['secrets']:
		print "Tags need to be unique."
		exit(1)

	p_date = (datetime.now() + timedelta(days=+(db['policy']['expires_in']))).isoformat()
	entry = {
			r'password': generatePassword(db['policy']),
			r'prev_password': None,
			r'expires': p_date,
			r'added': str(datetime.now().isoformat()),
			r'accessed': None,
			r'username': username,
			r'system': system,
	}

	db['secrets'][tag] = entry
	return db

def editRecord(record, attribute, newValue):
	'''
	Edit the given tag, updating the attribute with the new value
	'''
	record[attribute] = newValue
	return record

def viewRecord(record):
	'''
	Takes a JSON object and pretty-prints it. It also manipulates the datye string to be more readable.
	'''
	if record['accessed']:
		record['accessed'] = trimDateTime(record['accessed'])
	record['added'] = trimDateTime(record['added'])
	record['expires'] = trimDateTime(record['expires'])
	print json.dumps(record, separators=(',', ':'), sort_keys=True, indent=4)
	
def trimDateTime(isodatetime):
	'''
	Utility function for trimming out the fluff in ISO date-times.
	'''
	return isodatetime.replace('T', ' ', 1)[:-7]

def searchRecords(db, term):
	'''
	Search the JSON DB's tags for "term"
	'''
	secrets = [tag for tag in db if term in tag]
	if len(secrets) > 0:
		for secret in secrets:
			viewRecord(db[secret])
		return secrets

def deleteRecord(db, tag):
	'''
	Delete an existing record from the database.
	'''
	if tag in db['secrets']:
		del db['secrets'][tag]
		return db

def dumpRecords(data, compact=False):
	'''
	Dump all of the records, minus passwords
	'''
	
	if 'password' in data:
		del data['password']

	if not compact:
		print json.dumps(data, separators=(',', ':'), sort_keys=True, indent=4)
	else:
		print json.dumps(data)
		
def expiryCheck(record):
	'''
	Check if a password has expired or not.
	'''
	# Basic date check to make sure password hasn't expired
	c_date = datetime.now().isoformat()
	p_date = record['expires']
	if p_date < c_date:
		print "This record's password has expired - generating a new one."
		record['prev_password'] = record['password']
		record['password'] = generatePassword(data['policy'])
		record['expires'] = (datetime.now()+timedelta(days=+data['policy']['expires_in'])).isoformat()

	return record

def encryptDatabase(secretkey, data):
	'''
	Utilise the Crypto library and implement AES-256-CFB encryption to the database.
	We don't use temporary files here - everything is kept in variables and therefore memory (we hope).
	'''
	IV = Random.new().read(16)
	engine = AES.new(secretkey, AES.MODE_CFB, IV)

	if exists(THE_VAULT):
		backupDatabase()
		fd = open("{0}.swap".format(THE_VAULT), 'wb')
		if fd:
			jdata = json.JSONEncoder().encode(data)
			fd.write(IV + engine.encrypt(jdata))
			fd.close()
			move("{0}.swap".format(THE_VAULT), THE_VAULT)
		else:
			print "Problem opening database."
			exit(1)
	else:
		print "Unable to find database file."
	
def decryptDatabase(secretkey):
	'''
	Decrypt the database. We utilise AES-256-CFB mode.
	'''
	if exists(THE_VAULT):
		fd = open(THE_VAULT, 'rb')
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
	
def getSecret(doubleCheck=False):
	'''
	Get the user's secret key
	'''
	skey_1 = getpass('Secret Key: ')
	if doubleCheck:
		skey_2 = getpass('Secret Key (again): ')
		if not skey_1 == skey_2:
			print "Your secret keys do not match."
			exit(1)
	
	return PBKDF2(skey_1, SKEY_SALT).read(32)	

def main():
	'''
	Our application entry point.
	'''

	# Set up and handle argument parsing
	from argparse import ArgumentParser
	ap = ArgumentParser()

	# Database options
	ap.add_argument('-c', dest='create', help='Create a new database', action='store_true')

	# Database record handling options
	ap.add_argument('-a', metavar='tag', dest='add', help='Add a new record, auto-generating a password')
	ap.add_argument('-d', metavar='tag', dest='delete', help='Delete the given tag')
	ap.add_argument('-e', metavar='tag', dest='edit', help='Edit the given tag')
	ap.add_argument('-v', metavar='tag', dest='view', help='View an individual record/tag')
	ap.add_argument('-s', metavar='term', dest='search', help='Perform a search within the database')
	ap.add_argument('-p', metavar='tag', dest='password', help='View only the password for a given tag')
	ap.add_argument('-r', metavar='tag', dest='rotate', help='Rotate password for given tag')

	# Optionals to the above
	ap.add_argument('-U', metavar='username', dest='username', help='Username for the given tag')
	ap.add_argument('-S', metavar='system', dest='system', help='System for the given tag, such as an IP or hostname/URL')

	# Database policy options
	ap.add_argument('--policy', dest='policy', help='Display the database policies', action='store_true')
	ap.add_argument('--pwlen', metavar='len', dest='pwlen', help='Update the policy password length', type=int)
	ap.add_argument('--nosymbols', dest='symbols', help='Turn off symbols in passwords', action='store_true')
	ap.add_argument('--expires', metavar='days', dest='expires', help='Set the number of days the password expires', type=int)
	ap.add_argument('--autorenew', dest='autorenew', help='Turn on or off auto password refresh.', action='store_true')

	# Database record exporting
	ap.add_argument('-j', '--compact-json', dest='json', help='Dump the database: compact and ugly.', action='store_true')
	ap.add_argument('-J', '--pretty-json', dest='pjson', help='Dump the database: verbose and pretty.', action='store_true')

	args = ap.parse_args()
	
	# Check the database exists before trying to do anything else
	if not exists(THE_VAULT) or args.create:
		skey = getSecret(True)
		data = createDatabase()
		encryptDatabase(skey, data)
	else:
		skey = getSecret()
		
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
			
		encryptDatabase(skey, data)
		print "New entry for '{0}'; password: {1}".format(args.add,	data['secrets'][args.add]['password'])

	# DELETE RECORD
	if args.delete:
		data = decryptDatabase(skey)
		data = deleteRecord(data, args.delete)
		encryptDatabase(skey, data)
		print "Deleted '{0}'".format(args.delete)

	# EDIT RECORD
	if args.edit:
		data = decryptDatabase(skey)
		record = data['secrets'][args.edit]
		record = expiryCheck(record)
		
		if not args.username and not args.system:
			print "No attribute given. Nothing to edit."
			exit(1)
		
		if args.username:
			record = editRecord(record, 'username', args.username)
		
		if args.system:
			record = editRecord(record, 'system', args.system)
			
		data['secrets'][args.edit] = record
		encryptDatabase(skey, data)
	
	# VIEW RECORD
	if args.view:
		data = decryptDatabase(skey)
		if args.view in data['secrets']:
			viewRecord(data['secrets'][args.view])
			data['secrets'][args.view]['accessed'] = datetime.now().isoformat()
			encryptDatabase(skey, data)
		else:
			print "That record doesn't exist."
			exit(1)

	# VIEW PASSWORD
	if args.password:
		data = decryptDatabase(skey)
		if args.password in data['secrets']:
			print "{0}".format(data['secrets'][args.password])
			data['secrets'][args.password]['accessed'] = datetime.now().isoformat()
			encryptDatabase(skey, data)
		else:
			print "That record doesn't exist."
			exit(1)
		
	# SEARCH DATABASE
	if args.search:
		data = decryptDatabase(skey)
		#results = searchRecords(data['secrets'], args.search)
		secrets = [tag for tag in data['secrets'] if args.search in tag]
		for secret in secrets:
			print "Found: {0}".format(secret)
			viewRecord(data['secrets'][secret])
			data['secrets'][secret]['accessed'] = datetime.now().isoformat()
		encryptDatabase(skey, data)
			
	# CYCLE PASSWORD
	if args.rotate:
		data = decryptDatabase(skey)
		data['secrets'][args.rotate]['password'] = generatePassword(data['policy'])
		encryptDatabase(skey, data)

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
