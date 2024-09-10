#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2024-09-09

# developed with Fedora 38 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html
# I don't know if the following is still needed...
# dnf install python3-IPy

__version__ = '2024.09.09'
import sys, getopt
import ipaddress
from binascii import *
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from Cryptodome.Hash import cSHAKE128

def det_orchid(raa, hda, hi):
	# set some defaults
	# ORCHID PREFIX = 2001:30/28 = b0010 0000 0000 0001:0000 0000 0011/28
	# HID = RAA (always 14 bits) + HDA (always 14 bits) = 10 + 20 = b00 0000 0000 1010 + b00 0000 0000 0001 0100

	b_prefix = '0010000000000001000000000011' # RFC 9374 Section 8.2.1
#	h_prefix = '2001003'

	b_ogaid = '00000101' # suiteid of 5, RFC 9374 Section 8.2.2
	ContextID = unhexlify("00B5A69C795DF5D5F0087F56843F2C40")


	#format the HID from raa and HDA
#	print("raa:", raa)
#	print("RAA:", f'{raa:014b}')
#	print("hda:", hda)
#	print("HDA:", f'{hda:014b}')
	b_hid = f'{raa:014b}' + f'{hda:014b}'
#	print("HID:", b_hid)

	# perform hash with cSHAKE using input data
	h_orchid_left = unhexlify(b_prefix + b_hid + b_ogaid)
#	print(h_orchid_left.hex())
	shake =  cSHAKE128.new(custom = ContextID)
#	print(type(h_orchid_left))
#	print(type(hi), hi)
	shake.update((h_orchid_left + hi))
	h_hash = shake.read(8).hex()

	# format orchid in binary
	h_orchid = hex(int(b_prefix + b_hid + b_ogaid, 2))[2:] + h_hash
	orchid = 2

	print("DET:", h_orchid)
	# add in ':' for IPv6
	hiprr = base64.b64encode(hi).decode('ascii')
#	print("HIP RR: IN  HIP ( 5 ", h_orchid, "\n        ", hiprr, ")")
	#, hiprr[52:].zfill(52), ")")
	str_orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	print("DET:", str_orchid)

	return h_orchid

print("CSR Gen Version: ", __version__)
# set some defaults
keyname = 'keyfile'
passwd = ''
suiteid = 5
raa = 0  # e.g. 16376
hda = 0  # e.g. 20
det = "none"
serialnumber = "none"
ccaid = "none"
createkeyname = True

# handle cmdline args
try:
	opts, args = getopt.getopt(sys.argv[1:],"hn:p:c:",["serialnumber=","keyname=","passwd=","raa=","hda=", "keynameexists="])
except getopt.GetoptError:
	print('Error')
	sys.ext(2)

# parse the args
for opt, arg in opts:
	if opt == '-h':
		print('det-gen.py [-s, --serialnumber] <serialnumber> [-n,--keyname] <keyname> [-p,--passwd] <password> [--raa <RAA:10>] [--hda <HDA:20>] --keynameexists <y/n>]')
		sys.exit()
	elif opt in ("-s", "--serialnumber"):
		serialnumber = arg
	elif opt in ("-n", "--keyname"):
		keyname = arg
	elif opt in ("-p", "--passwd"):
		passwd = arg
	elif opt == '--raa':
		raa = int(arg)
	elif opt == '--hda':
		hda = int(arg)
	elif opt == '--keynameexists':
		if arg == 'n' or arg == 'N':
			createkeyname = True
			print("No")
		else:
			createkeyname = False
			print("yes")

if serialnumber == "none":
	print("Error - No Serial Number")
	sys.ext(2)

# Not really using keyfile password :(

if createkeyname:
	# Generate our key
	private_key = ed25519.Ed25519PrivateKey.generate()
	public_key = private_key.public_key()
	public_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw)
	
	# Write our key to disk for safe keeping
	
	with open(keyname + "prv.pem", "wb") as f:
		f.write(private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption(),
			))
else:
	with open(keyname + "prv.pem", "rb") as f:
		keyname_pkkey = f.read()
	f.close()
	private_key = load_pem_private_key(keyname_pkkey, None)
	public_key = private_key.public_key()
	public_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw)



if raa == 0:
	print("No RAA provided.  A DET will not be generated")
	det = 0
	det_int = 0
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		# Provide various details about who we are.
		x509.NameAttribute(NameOID.SERIAL_NUMBER, serialnumber),
		#    x509.NameAttribute(NameOID.COMMON_NAME, ccaid),
		])
		# Sign the CSR with our private key.
		).sign(private_key, None)

else:
#	print("RAA: ", raa)
#	print("HDA: ", hda)
	hi = public_bytes.hex()
	det = det_orchid(raa, hda, bytes(hi, 'utf-8'))
	det_int = int(bytes(det, 'utf-8'),16)
	#print("here", type(det), det)
	#print("here2", type(det_int), det_int)
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		# Provide various details about who we are.
		x509.NameAttribute(NameOID.SERIAL_NUMBER, serialnumber),
		#    x509.NameAttribute(NameOID.COMMON_NAME, ccaid),
		])
		).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv6Address(det_int))]),critical=True,
		# Sign the CSR with our private key.
		).sign(private_key, None)

# Write our CSR out to disk.

with open(keyname + "csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))
