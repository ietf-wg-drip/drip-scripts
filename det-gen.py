#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2023-04-21

# developed with Fedora 35 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html


__version__ = '2023.04.01'

import sys, getopt
from subprocess import call, DEVNULL

import hashlib
import math
from binascii import *
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import cSHAKE128

DATA_SET_SIZE = 1000000

def det_orchid(rra, hda, hi):
	# ORCHID PREFIX = 2001:30/28 = b0010 0000 0000 0001:0000 0000 0011/28
	# HID = RRA (always 14 bits) + HDA (always 14 bits) = 10 + 20 = b00 0000 0000 1010 + b00 0000 0000 0001 0100

	b_prefix = '0010000000000001000000000011' # RFC 9374 Section 8.2.1
	h_prefix = '2001003'
	suiteid = 5

	b_ogaid = '00000101' # RFC 9374 Section 8.2.2
	h_ogaid = suiteid
	ContextID = unhexlify("00B5A69C795DF5D5F0087F56843F2C40")


	#format the HID from RRA and HDA
#	print("RRA:", rra)
#	print("RRA:", f'{rra:014b}')
#	print("HDA:", f'{hda:014b}')
	b_hid = f'{rra:014b}' + f'{hda:014b}'
#	print("HID:", b_hid)

	# perform hash with cSHAKE using input data
	h_orchid_left = unhexlify(b_prefix + b_hid + b_ogaid)
#	print(h_orchid_left.hex())
	shake =  cSHAKE128.new(custom = ContextID)
	shake.update((h_orchid_left + hi))
	h_hash = shake.read(8).hex()
#	print(h_hash)

	# format orchid in binary
	h_orchid = hex(int(b_prefix + b_hid + b_ogaid, 2))[2:] + h_hash

	# add in ':' for IPv6
	orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	print("DET:", h_orchid)
	print("DET:", orchid)
	return orchid

def main(argv):
	print("DET Gen Version: ", __version__)
	# set some defaults
	passwd = ''
	suiteid = 5
	rra = 16376
	hda = 20

	createdataset = False

	# handle cmdline args
	try:
		opts, args = getopt.getopt(argv,"hn:p:",["passwd=","suiteid=","rra=","hda=", "dataset="])
	except getopt.GetoptError:
		print('Error')
		sys.ext(2)

	# parse the args
	for opt, arg in opts:
		if opt == '-h':
			print('det-gen.py [-p,--passwd] <password> [--suiteid <HIT Suite ID:4> --rra <RRA:10> --hda <HDA:20> --dataset <y/n>]')
			sys.exit()
		elif opt in ("-p", "--passwd"):
			passwd = arg
		elif opt == '--suiteid':
			suiteid = arg
		elif opt == '--rra':
			rra = arg
		elif opt == '--hda':
			hda = arg
		elif opt == '--dataset':
			if arg == 'y' or arg == 'Y':
				createdataset = True
			else:
				createdataset = False

	# show value we will be using
	print("Using the following value for DET generation:")
	print("KEY PASSWORD: ", passwd)
	print("HHIT Suite ID: ", suiteid)
	print("RRA: ", rra)
	print("HDA: ", hda)
	key = ECC.generate(curve='ed25519')
	f = open('myprivatekey.pem','wt')
	f.write(key.export_key(format='PEM'))
	f.close()
	f = open('myprivatekey.pem','rt')
	prkey = ECC.import_key(f.read())
#	print("EdDSA: ", prkey)
	f = open('mypublickey.pem','wt')
	pbkey = key.public_key()
	pbpem = key.public_key().export_key(format="PEM")
#	print("EdDSA: ", pbkey)
#	print("EdDSA: ", pbpem)
	f.write(pbpem)
	f.close()
	pbraw = key.public_key().export_key(format="raw")
	print("HI: ", pbraw.hex())
	det = det_orchid(rra, hda, pbraw)



if __name__ == "__main__":
	main(sys.argv[1:])
