#!/bin/python
from __future__ import print_function
from  binascii import hexlify
import hashlib
import base64
from getpass import getpass
import sys
import pyperclip
charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
chameleon_charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789?!#@&$="
numbers = "123456789"
letters = "ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
punct = "?!#@&$"

def hashify(item):
	m = hashlib.sha1()
	m.update(item)
	return m.digest()

def generate(secretpassword, sitename):
    chained = "{0}:{1}".format(secretpassword,sitename.lower())
    secret_hash = hashify(chained)
    base64_secret =   base64.b64encode(secret_hash)[:10]
    encoded_secret = change_encoding(base64_secret)
    pwd = ensurenumberandletter(encoded_secret)
    return pwd

def change_encoding(s):
	encoded = ""
	for character in s:
		index = charset.index(character)
		encoded = encoded + chameleon_charset[index]
	return encoded

def ensurenumberandletter(s):
	
    hasnumber = False
    hasletter = False
    haspunct = False

    for character in s:
    	if character in numbers:
    		hasnumber = True
    	if character in letters:
    		hasletter = True
    	if character in punct:
    		haspunct = True

    if not hasnumber:
        s = "1" + s[1:]
    if not hasletter:
    	s = s[:1] + "a" + s[2:]
    if not haspunct:
    	s = s[:2] + "@" + s[3:]
    return s

def main(args):
    if len(args) != 2:
        print("invalid arguments. usage: {0} <hostname>".format(sys.argv[0]))
        return

    _,hostname = tuple(args)
    print("generating password for hostname: {0}".format(hostname))
    master_passwd = getpass("enter the master password: ")
    generated_passwd = generate(master_passwd, hostname)
    print("generated password: {} (copied to clipboard)".format(generated_passwd))
    pyperclip.copy(generated_passwd)

if __name__ == "__main__":
    try:    
        main(sys.argv)
    except KeyboardInterrupt: 
        print("\nbye!")
        pass
