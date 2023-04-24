#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2023-04-24

# developed with Fedora 37 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html
# dnf install python3-pynacl

__version__ = '2023.04.01'

import time
import datetime
from binascii import *
from Cryptodome.PublicKey import ECC
# there is probably a way for nacl to read the privatekey.pem file for the secret and not need this.
from nacl.signing import SigningKey

vnb = "04/01/2023"
vna = "04/01/2024"

element = datetime.datetime.strptime(vnb,"%m/%d/%Y")
tuple = element.timetuple()
vnbtime = time.mktime(tuple)
element = datetime.datetime.strptime(vna,"%m/%d/%Y")
tuple = element.timetuple()
vnatime = time.mktime(tuple)


# print(vnb, " ", hex(int(vnbtime))[2:])
# print(vna, " ", hex(int(vnatime))[2:])
# print(f'{hex(int(vnbtime)):032b}' + f'{hex(int(vnatime)):032b}')

DETofC = hex(0x2001003ffe0014050b27c442f9d62167)[2:]
HIofC = hex(0x4a1232bc278359939e3555bf5393bc5b2abd57c7c3b269622d06c164b9795f07)[2:]
DETofP = hex(0x2001003ffe0014054a12792a41175eb9)[2:]

pleasesign = hex(int(vnbtime))[2:] + hex(int(vnatime))[2:] + DETofC + HIofC + DETofP

f = open('myprivatekey.pem','rt')
prkey = ECC.import_key(f.read())

# print("seed: ", prkey.seed)
# print(pleasesign)

sk = SigningKey(prkey.seed)
mysig = sk.sign(bytes.fromhex(pleasesign)).signature
# print(len(mysig), str(hexlify(mysig))[2:-1])

endorsement = pleasesign + str(hexlify(mysig))[2:-1]

print(len(endorsement) , endorsement)
