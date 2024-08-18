#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2023-05-02

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
#vna="06/01/2023"
#MsgID="01"
#A2Xmsg="00570000d2d5c31936730dd38a08fa0800004c00"
#HDAonUSendorse="6449f34066306cc02001003ffec00005e52187f90d5f284ff1a756a6c5e4baddb67718f2dd9227fad037b3feb677e7033673ef172b05d3762001003000000005d0e8f31bc53275f2428c89a584511f7f02903cd9b16d44a3c1e1c68f6456ae12e64c455c3e32de21190905858c279c3e1d7789b2e642a80544de5b9af822448698db547107d2ea0f"
#pkeyname="testhda16376-16376"

# all of these variables can be overridden via the command line
#
# e.g.
#python a2x1.py --commandfile=root.dat --vnb="06/01/2023" --pkeyname=root
#
# A2Xmsg and HDAonUSendorse are potentially too long to type into the command line.
#    Leave them for the commandfile.

__version__ = '2023.05.01'

import sys, getopt
import time
import datetime
from binascii import *
from Cryptodome.PublicKey import ECC
# there is probably a way for nacl to read the privatekey.pem file for the secret and not need this.
from nacl.signing import SigningKey

commandfile = "a2x.dat"
vna = "04/01/2024"
MsgID="01"
A2Xmsg="00570000d2d5c31936730dd38a08fa0800004c00"
DETofUA="2001003ffe3ff8058eb731967e482934"
HDAonUAendorse="6449f34066306cc02001003ffec00005e52187f90d5f284ff1a756a6c5e4baddb67718f2dd9227fad037b3feb677e7033673ef172b05d3762001003000000005d0e8f31bc53275f2428c89a584511f7f02903cd9b16d44a3c1e1c68f6456ae12e64c455c3e32de21190905858c279c3e1d7789b2e642a80544de5b9af822448698db547107d2ea0f"
pkeyname = "testhda1"

try:
	opts, args = getopt.getopt(sys.argv[1:],"hn:p:c:",["commandfile=","pkeyname=","passwd=","vna="])
except getopt.GetoptError:
	print('Error')
	sys.ext(2)

#	parse the args
for opt, arg in opts:
	if opt == '-h':
		print('a2x1.py [-c,--commandfile] <parent commandfile> ')
		sys.exit()
	elif opt in ("-c", "--commandfile"):
		commandfile = arg
	elif opt in ("-k", "--pkeyname"):
		pkeyname = arg
	elif opt in ("-p", "--passwd"):
		passwd = arg
	elif opt == '--vna':
		vna = arg


file1 = open(commandfile, 'r')
a = True
while a:
	line = file1.readline()
#	print(line.strip())
	if not line:
		a = False
	exec("%s" % line.strip())
file1.close()

print(vna)
print(MsgID)
print(A2Xmsg)
print(HDAonUAendorse)
#print(pkeyname)

element = datetime.datetime.strptime(vna.strip(),"%m/%d/%Y")
tuple = element.timetuple()
vnatime = time.mktime(tuple)
#print(vna, hex(int(vnatime))[2:].zfill(8))

compressendorse = HDAonUAendorse[:16] + HDAonUAendorse[48:]
#print(compressendorse)

pleasesign = hex(int(vnatime))[2:].zfill(8) + MsgID + A2Xmsg + compressendorse


#print(pleasesign)

pkfile = pkeyname + "prv.pem"

f = open(pkfile,'rt')
prkey = ECC.import_key(f.read())
f.close()

#	print("seed: ", prkey.seed)

sk = SigningKey(prkey.seed)
mysig = sk.sign(bytes.fromhex(pleasesign)).signature
#	print(len(mysig), str(hexlify(mysig))[2:-1])

sigA2Xmsg = pleasesign + str(hexlify(mysig))[2:-1]

print("sigA2Xmsg(", len(sigA2Xmsg)/2, " bytes):" , sigA2Xmsg)

pleasesign = hex(int(vnatime))[2:].zfill(8) + MsgID + A2Xmsg + DETofUA

#print(pleasesign)

mysig = sk.sign(bytes.fromhex(pleasesign)).signature
#print(len(mysig), str(hexlify(mysig))[2:-1])

sigA2Xmsg = pleasesign + str(hexlify(mysig))[2:-1]

print("sigA2Xmsg(", len(sigA2Xmsg)/2, " bytes):" , sigA2Xmsg)
