#!/bin/python
from __future__ import print_function
from  binascii import hexlify
import hashlib
import base64
from getpass import getpass
import sys
import argparse
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

def copy_passwd_to_clipboard(passwd):
    try:
        import pyperclip
        pyperclip.copy(passwd)
    except ImportError: 
        print("cannot copy to clipboard because the pyperclip package is not installed.")

def main(args):
    print("generating password for site: {0}".format(args.sitename))
    master_passwd = getpass("enter the master password: ")
    generated_passwd = generate(master_passwd, args.sitename)
    print("generated password: {}".format(generated_passwd))
    if args.copy:
        copy_passwd_to_clipboard(generated_passwd)


if __name__ == "__main__":
    try:    
        parser = argparse.ArgumentParser()
        parser.add_argument("-n","--sitename", help="the sitename to generated password to", type=str, required=True)
        parser.add_argument("-c","--copy", help="copy to clipboard", action="store_true", default=False)
        args = parser.parse_args()
        main(args)
    except KeyboardInterrupt: 
        print("\nbye!")
        pass