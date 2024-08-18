#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2023-05-7

# developed with Fedora 37 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html
# dnf install python3-pynacl

# one manditory file and one optional file needed.

# Manditory is a pem private key file
#		File name is <something>prv.pem
#		<something> is the variable pkeyname

# Optional file is a file of commands to set the various variables
#	The file name is --commandfile=<something> on the command line
#		defautl is det.dat
#
# sample content is:
#
#vnb="04/01/2023"
#vna="04/01/2024"
#DETofC=0x20010030000000050eda8a644093aadd
#HIofC=0xf0beded7c542fcefd620f5f3f3b5f95627f50a308e1dacfe507adc62c322101c
#DETofP=0x20010030000000050eda8a644093aadd
#pkeyname=root

# all of these variables can be overridden via the command line
#
# e.g.
#python endorse.py --commandfile=root.dat --vnb="06/01/2023" --pkeyname=root
#
# for self-endorsements (--self=y on command line):
#	use HIofC for the HI of the signer, DET0fP and private pem key of signer as well.

__version__ = '2023.05.01'

import sys, getopt
import time
import datetime
from binascii import *
import base64
from Cryptodome.PublicKey import ECC
# there is probably a way for nacl to read the privatekey.pem file for the secret and not need this.
from nacl.signing import SigningKey

commandfile = "det.dat"
vnb = "04/01/2023"
vna = "04/01/2024"
DETofC = hex(0x2001003ffe0014050b27c442f9d62167)[2:]
HIofC = hex(0x4a1232bc278359939e3555bf5393bc5b2abd57c7c3b269622d06c164b9795f07)[2:]
DETofP = hex(0x2001003ffe0014054a12792a41175eb9)[2:]
pkeyname = "parent"
createself = False

try:
	opts, args = getopt.getopt(sys.argv[1:],"hn:p:c:",["commandfile=","pkeyname=","passwd=","vnb=","vna=", "self="])
except getopt.GetoptError:
	print('Error')
	sys.ext(2)

#	parse the args
for opt, arg in opts:
	if opt == '-h':
		print('endorse.py [-c,--commandfile] <parent commandfile> <parent keyname> [-k --pkeyname, will be appended with prv.pem  -p,--passwd <password> --vnb <Not Before date:04/01/2023> --vna <vna <Not After date:04/01/2023> --self <y/n>]')
		sys.exit()
	elif opt in ("-c", "--commandfile"):
		commandfile = arg
	elif opt in ("-k", "--pkeyname"):
		pkeyname = arg
	elif opt in ("-p", "--passwd"):
		passwd = arg
	elif opt == '--vnb':
		vnb = arg
	elif opt == '--vna':
		vna = arg
	elif opt == '--self':
		if arg == 'y' or arg == 'Y':
			createself = True
		else:
			createself = False

file1 = open(commandfile, 'r')
a = True
while a:
	line = file1.readline()
#	print(line.strip())
	if not line:
		a = False
	exec("%s" % line.strip())
file1.close()

#print(vnb)
#print(vna)
#print(hex(DETofC)[2:])
#print(hex(HIofC)[2:])
#print(hex(DETofP)[2:])
#print(pkeyname)

element = datetime.datetime.strptime(vnb.strip(),"%m/%d/%Y")
tuple = element.timetuple()
vnbtime = time.mktime(tuple)
#print(vnb, hex(int(vnbtime))[2:])

element = datetime.datetime.strptime(vna.strip(),"%m/%d/%Y")
tuple = element.timetuple()
vnatime = time.mktime(tuple)
#print(vna, hex(int(vnatime))[2:])
#print(hex(DETofC)[2:].zfill(32))
#print(hex(HIofC)[2:].zfill(64))
#print(hex(DETofP)[2:].zfill(32))

if createself:
	pleasesign = hex(int(vnbtime))[2:].zfill(8) + hex(int(vnatime))[2:].zfill(8) + hex(HIofC)[2:].zfill(64) + hex(DETofP)[2:].zfill(32)
else:
	pleasesign = hex(int(vnbtime))[2:].zfill(8) + hex(int(vnatime))[2:].zfill(8) + hex(DETofC)[2:].zfill(8) + hex(HIofC)[2:].zfill(64) + hex(DETofP)[2:]


# print(pleasesign)

pkfile = pkeyname + "prv.pem"

f = open(pkfile,'rt')
prkey = ECC.import_key(f.read())
f.close()

#	print("seed: ", prkey.seed)

sk = SigningKey(prkey.seed)
mysig = sk.sign(bytes.fromhex(pleasesign)).signature
# print(len(mysig), str(hexlify(mysig))[2:-1])

endorsement = pleasesign + str(hexlify(mysig))[2:-1]
print("Endorsement(", len(endorsement)/2, " bytes):" , endorsement)

# CERT RR is **ONLY** for Broadcast, i.e. 136 byte version, not self- 120 bytes...
# 0c060a2b06010401b43b020606 created by prefixing the following with length 0c:
# >>> from pyasn1.type import univ
# >>> from pyasn1.codec.der.decoder import decode as der_decoder
# >>> from pyasn1.codec.der.encoder import encode as der_encoder
# >>> import binascii
# >>> oid = univ.ObjectIdentifier('1.3.6.1.4.1.6715.2.6')
# >>> s = der_encoder(oid)
# >>> print(binascii.hexlify(s))
# 060a2b06010401b43b02060

certrr = (base64.b64encode(bytes.fromhex("0c060a2b06010401b43b020606"+endorsement))).decode('ascii')
print("CERT RR:\n IN  CERT 254 0 0 (",certrr[:50],"\n",certrr[50:100],"\n",certrr[100:150],"\n",certrr[150:200], ")","\n")
