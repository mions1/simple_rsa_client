""" Author: Simone Mione
"""

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

import base64
import os

def generate_keys(bit_lenght=2048, passphrase="password", save=True):
	""" Generate public and private keys.

	Args:
		bit_lenght (int, optional): key lenght. Defaults to 2048.
		passphrase (str, optional): passphrase used to export private key.
		save (bool, optional): If true, generated key will be saved on files. Defaults to True.

	Returns:
		dict: A dict with "public_key" and "private_key"
	"""
	keys = RSA.generate(bit_lenght)

	public_key = keys.publickey().exportKey()
	private_key = keys.exportKey(passphrase="password")

	keys = {"public_key": public_key,\
		"private_key": private_key}

	if save:
		save_keys(keys)

	return keys

def save_keys(keys, public_file="public_key", private_file="private_key"):
	""" Save keys on file.

	Args:
		keys (dict): keys to store, computed by generate_key
		public_file (str, optional): file name to store public key. Defaults to "public_key".
		private_file (str, optional): file name to store private key. Defaults to "private_key".
	"""
	public_key = keys["public_key"]
	private_key = keys["private_key"]

	with open(public_file, "wb") as f:
		f.write(public_key)
	
	with open(private_file, "wb") as f:
		f.write(private_key)

def load_keys(public_file="public_key", private_file="private_key", passphrase="password"):
	""" Load keys from files.

	Args:
		public_file (str, optional): fila name of public key. Defaults to "public_key".
		private_file (str, optional): file name of private key. Defaults to "private_key".
		passphrase (str, optional): passphrase of the private key. Defaults to "password".

	Returns:
		dict: return the keys dict. Return false if there is no files
	"""
	if not os.path.exists(public_file) \
		or not os.path.exists(private_file):
		return False
	keys = dict()
	keys["public_key"] = (RSA.importKey(open(public_file).read())).exportKey()
	keys["private_key"] = RSA.importKey(open(private_file).read(), passphrase).exportKey()
	
	return keys

def encryption(message, key):
	""" Encrypt the message with the key

	Args:
		message (str): message to encrypt
		key (str): key for encryption

	Returns:
		str: cipher message
	"""
	key = RSA.importKey(key)
	rsa = PKCS1_OAEP.new(key)
	cipher_message = rsa.encrypt(message.encode("utf-8"))
	cipher_message = base64.b64encode(cipher_message).decode()
	return cipher_message

def decryption(cipher_message, key):
	""" Decrypt the cipher message with the key

	Args:
		cipher_message (str): cipher message to decrypt
		key (str): key for decryption

	Returns:
		str: decrypted message
	"""
	key = RSA.importKey(key, "password")
	rsa = PKCS1_OAEP.new(key)
	cipher_message = base64.b64decode(cipher_message.encode())
	message = rsa.decrypt(cipher_message)
	message = message.decode()
	return message

if __name__=="__main__":

	print("Do you want:\n 1. Generate new keys\n 2. Load from files?")
	choose = int(input())

	if choose == 1:
		keys = generate_keys()
	elif choose == 2:
		keys = load_keys()
		if not keys:
			print("No file public_key and/or private_key found. New keys are generated...")
			keys = generate_keys()

	public_key = keys["public_key"]
	private_key = keys["private_key"]

	save_keys(keys)

	choose = 4
	while choose != 0:
		print("Do you want:\n 1. Encrypt\n 2. Decrypt\n 3. Decrypt the last message you have encrypted?\nType 0 to exit")
		choose = int(input())

		if choose == 1:
			message = input("Write a message to encrypt: ")
			cipher = encryption(message, public_key)
			print("---------------- CHIPHER MESSAGE IS ----------- ")
			print(cipher)
		
		elif choose == 2:
			cipher_msg = input("Write the cipher message: ")
			message = decryption(cipher_msg, private_key)
			print("----------------- PLAIN MESSAGE ---------------")
			print(message)

		elif choose == 3:
			if not cipher:
				print("WANING: To choose this option, you have to perform an encryption first")
				continue
			message = decryption(cipher, private_key)
			print("----------------- PLAIN MESSAGE ---------------")
			print(message)


		