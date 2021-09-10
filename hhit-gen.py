#!/bin/python

# AXEnterprize, LLC
# Adam Wiethuechter <adam.wiethuechter@axenterprize.com>
# 2019-08-15

__version__ = '2019.08a11'

import sys, getopt
from subprocess import call, DEVNULL

import hashlib
import math
from binascii import *

DATA_SET_SIZE = 1000000

def make_keypair(name, passw):
	kname = name + '.pem'
	kpass = 'pass:' + passw
	ret = call(['openssl', 'genpkey', '-aes256', 
				'-algorithm', 'ed25519', '-outform',
				'pem', '-pass', kpass, '-out', kname],
				stdout=DEVNULL, stderr=DEVNULL)
	if (not ret):
		print("Successfully created ED25519 keypair of name: ", kname)
	else:
		print("Failed to create ED25519 keypair!")

def extract_privkey(name, passw):
	kname = name + '.pem'
	kpass = 'pass:' + passw
	# this outputs to stdout by default
	ret = call(['openssl', 'pkey', '-inform',
				'pem', '-in', kname, '-text', 
				'-noout', '-passin', kpass],
				stdout=DEVNULL, stderr=DEVNULL)
	if (not ret):
		print("Successfully extracted private key from file: ", kname)
	else:
		print("Failed to extract private key!")

def extract_pubkey(name, passw):
	kname = name + '.pem'
	kpass = 'pass:' + passw
	dname = name + '.pub'
	'''
	ret = call(['openssl', 'pkey', '-in', 
				kname, '-out', dname, '-outform',
				'DER', '-pubout', '-passin', kpass],
				stdout=DEVNULL, stderr=DEVNULL)
	'''
	# seeing as I can't figure out how to decode DER formats
	# revert to standard PEM format for now
	ret = call(['openssl', 'pkey', '-inform', 
				'pem', '-in', kname, '-out',
				dname, '-pubout', '-passin', kpass],
				stdout=DEVNULL, stderr=DEVNULL)
	if (not ret):
		print("Successfully extracted pub key out to file: ", dname)
	else:
		print("Extraction of public key failed!")

def encode_func(binput, length, size):
	halfsize = math.floor(size / 2)
	halflen = math.floor(length / 2)
	start = halfsize - halflen
	end = halfsize + halflen
	return binput[start:end]

def hit_orchid(bitstring, contextid):
	# ORCHID PREFIX = 2001:2/28 = b0010 0000 0000 0001:0000 0000 0010/28
	# OGA ID = bXXXX = 0100

	b_prefix = '0010000000000001000000000010' # RFC 7343 Section 2
	h_prefix = '2001002'

	b_ogaid = '0100' # draft, section 4.1.4
	h_ogaid = '4'

	# perform hash with sha1 using input data
	inputdatum = contextid + bitstring
	hashfunc = hashlib.sha1()
	hashfunc.update(inputdatum.encode())
	h_hash = hashfunc.hexdigest()

	# perform encoding
	b_hash = bin(int(h_hash, 16))[2:]
	b_encode = encode_func(b_hash, 96, len(b_hash))
	h_encode = str.format('{:016x}', int(b_encode, 2))

	# format orchid (prefix + ogaid + encode)
	h_orchid = h_prefix + h_ogaid + h_encode

	# add in ':' for IPv6
	orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	return orchid

def bin_to_hex(b_string):
	return hex(int(b_string, 16))[2:]

def hhit_orchid(rra, hda, bitstring, contextid):
	# ORCHID PREFIX = 2001:2/28 = b0010 0000 0000 0001:0000 0000 0010/28
	# OGA ID = bXXXX = 0100
	# HID = RRA (always 14 bits) + HDA (always 18 bits) = 10 + 20 = b00 0000 0000 1010 + b00 0000 0000 0001 0100

	b_prefix = '0010000000000001000000000010' # RFC 7343 Section 2
	h_prefix = '2001002'

	b_ogaid = '0100' # draft, section 4.1.4
	h_ogaid = '4'

	#format the HID from RRA and HDA
	b_rra = rra;
	for raa_len in range(14 - len(rra)):
		b_rra = '0' + b_rra
	b_hda = hda;
	for hda_len in range(18 - len(hda)):
		b_hda = '0' + b_hda
	h_hid = str.format('{:08x}', int(b_rra + b_hda, 2))

	# perform hash with sha1 using input data
	inputdatum =  contextid + (b_rra + b_hda + bitstring)
	hashfunc = hashlib.sha1()
	hashfunc.update(inputdatum.encode())
	h_hash = hashfunc.hexdigest()

	# perform encoding
	b_hash = bin(int(h_hash, 16))[2:]
	b_encode = encode_func(b_hash, 64, len(b_hash))
	h_encode = str.format('{:016x}', int(b_encode, 2))

	# format orchid (prefix + ogaid + encode) in binary
	h_orchid = h_prefix + h_ogaid + h_hid + h_encode

	# add in ':' for IPv6
	orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	return orchid

def hhit_gen(pubkey, raa, hda):
	ctxid = "F0EFF02FBFF43D0FE7930C3C6E6174EA"

	# convert everything to binary
	b_pubkey = bin(int(pubkey.encode("utf-8").hex(), 16))[2:] # pubkey is string, covert to hex, then int, then binary
	b_raa = bin(raa)[2:] # these should be ints coming in
	b_hda = bin(hda)[2:]
	b_ctxid = bin(int(ctxid, 16))[2:]

	# return hit_orchid(b_pubkey, b_ctxid)
	# print("Generated HIT: ", hit_orchid(b_pubkey, b_ctxid))
	return (hit_orchid(b_pubkey, b_ctxid), hhit_orchid(b_raa, b_hda, b_pubkey, b_ctxid))

def main(argv):
	print("HHIT Gen Version: ", __version__)
	# set some defaults
	keyname = ''
	passwd = ''
	suiteid = 4
	rra = 10
	hda = 20

	createdataset = False

	# handle cmdline args
	try:
		opts, args = getopt.getopt(argv,"hn:p:",["keyname=","passwd=","suiteid=","rra=","hda=", "dataset="])
	except getopt.GetoptError:
		print('Error')
		sys.ext(2)

	# parse the args
	for opt, arg in opts:
		if opt == '-h':
			print('hhit-gen.py [-n,--keyname] <keyname> [-p,--passwd] <password> [--suiteid <HIT Suite ID:4> --rra <RRA:10> --hda <HDA:20> --dataset <y/n>]')
			sys.exit()
		elif opt in ("-n", "--keyname"):
			keyname = arg
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
	print("Using the following value for HHIT generation:")
	print("KEY NAME: ", keyname)
	print("KEY PASSWORD: ", passwd)
	print("HIT Suite ID: ", suiteid)
	print("RRA: ", rra)
	print("HDA: ", hda)

	if createdataset:
		for datum in range(0, DATA_SET_SIZE):
			# perform key generation
			keynamed = keyname + str(datum)
			make_keypair(keynamed, passwd)
			extract_privkey(keynamed, passwd)
			extract_pubkey(keynamed, passwd)

			# read in public key - currently NOT in DER format
			filename = keynamed + ".pub"
			data = ''
			with open(filename, 'r') as f:
				for line in f:
					if '-' not in line:
						data += line[:-1]

			# generate our HHIT
			hhit = hhit_gen(data, rra, hda)
			print("Generated HIT is: ", hhit[0])
			print("Generated HHIT is: ", hhit[1])

			# place into file for safe keeping
			with open("hhit_set.txt", "a+") as f:
				f.write(keynamed + "," + hhit[0] + "," + hhit[1] + "\n")
	else:
		# perform key generation
		make_keypair(keyname, passwd)
		extract_privkey(keyname, passwd)
		extract_pubkey(keyname, passwd)

		# read in public key - currently NOT in DER format
		filename = keyname + ".pub"
		data = ''
		with open(filename, 'r') as f:
			for line in f:
				if '-' not in line:
					data += line[:-1]

		# generate our HHIT
		hhit = hhit_gen(data, rra, hda)
		print("Generated HIT is: ", hhit[0])
		print("Generated HHIT is: ", hhit[1])

		# place into file for safe keeping
		with open("hhit_set.txt", "w+") as f:
			f.write(keyname + "," + hhit[0] + "," + hhit[1] + "\n")


if __name__ == "__main__":
	main(sys.argv[1:])