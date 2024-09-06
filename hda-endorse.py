#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2024-09-03

# developed with Fedora 38 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html
# one manditory file and one optional file needed.

# Manditory is a pem HDA private key file
#		File name is <something>prv.pem
#		<something> is the variable hdakey
#			Passwording this file is not yet implemented

# Optional file is a file of commands to set the various variables
#	The file name is --commandfile=<something> on the command line
#		default is ua.dat
#
# sample content is:
#
#raa = 16376
#hda = 16376
#DETofHDA=0x20010030000000050eda8a644093aadd
#vnb="04/01/2024"
#vna="04/01/2025"
#hdakey="hda"
#uacsr="ua1"

# all of these variables can be overridden via the command line
#
# e.g.
#python endorse.py --commandfile=ua1.dat --vnb="06/01/2024" --hdakey=hda


__version__ = '2024-09-03'

import sys, getopt
import ipaddress
import time
import datetime
import random
from binascii import *
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Cryptodome.Hash import cSHAKE128


from Cryptodome.PublicKey import ECC

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
#	print(type(h_orchid_left),h_orchid_left)
#	print("hi",type(hi), hi)
	shake.update((h_orchid_left + hi))
	h_hash = shake.read(8).hex()

	# format orchid in binary
	h_orchid = hex(int(b_prefix + b_hid + b_ogaid, 2))[2:] + h_hash
#	orchid = 2

	print("UA DET:", h_orchid)
	# add in ':' for IPv6
	hiprr = base64.b64encode(hi).decode('ascii')
#	print("HIP RR: IN  HIP ( 5 ", h_orchid, "\n        ", hiprr, ")")
	#, hiprr[52:].zfill(52), ")")
	str_orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	print("UA DET:", str_orchid)

	return h_orchid

commandfile = "ua.dat"
DETofHDA=0x2001003ffe3ff8055077246573373664
vnb = "04/01/2024"
vna = "04/01/2025"
uacsr="ua1"
hdakey="hda"

# should extract raa and hda from DETofHDA
raa = 16376
hda = 16376

try:
	opts, args = getopt.getopt(sys.argv[1:],"hn:p:c:",["commandfile=","hdakey=","passwd=","vnb=","vna=", "raa=", "hda="])
except getopt.GetoptError:
	print('Error')
	sys.ext(2)

#	parse the args
for opt, arg in opts:
	if opt == '-h':
		print('endorse.py [-c,--commandfile] <UA commandfile> <UA keyname> [-k --hdakey, will be appended with prv.pem  -p,--passwd <password> --vnb <Not Before date:04/01/2023> --vna <vna <Not After date:04/01/2023> --raa nn --hda nn')
		sys.exit()
	elif opt in ("-c", "--commandfile"):
		commandfile = arg + ".dat"
	elif opt in ("-k", "--hdakey"):
		hdakey = arg
	elif opt in ("-p", "--passwd"):
		passwd = arg
	elif opt == '--vnb':
		vnb = arg
	elif opt == '--vna':
		vna = arg
	elif opt == '--raa':
		raa = arg
	elif opt == '--hda':
		hda = arg

file1 = open(commandfile, 'r')
a = True
while a:
	line = file1.readline()
#	print(line.strip())
	if not line:
		a = False
	exec("%s" % line.strip())
file1.close()

uacsr=uacsr + "csr.pem"
hdakey=hdakey + "prv.pem"
DETofHDA=hex(DETofHDA)[2:]

with open(hdakey, "rb") as f:
	hda_pkkey = f.read()
f.close()

hda_prkey = load_pem_private_key(hda_pkkey, None)
hda_prkey_bytes = hda_prkey.private_bytes(
	encoding=serialization.Encoding.Raw,
	format=serialization.PrivateFormat.Raw,
	encryption_algorithm=serialization.NoEncryption()
	)
#print("pr", type(hda_prkey_bytes), hda_prkey_bytes)
hda_pukey = hda_prkey.public_key()
hda_pukey_bytes = hda_pukey.public_bytes(
	encoding=serialization.Encoding.Raw,
	format=serialization.PublicFormat.Raw
	)
#print("pu", type(hda_pukey_bytes), hda_pukey_bytes)

with open(uacsr, "rb") as f:
	ua_pem_req_data = f.read()
f.close()

ua_csr = x509.load_pem_x509_csr(ua_pem_req_data)
ua_csr_pbkey = ua_csr.public_key()
#print("x",ua_csr_pbkey)

ua_public_bytes = ua_csr.public_key().public_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PublicFormat.Raw,)


#print("ua_hi",type(ua_public_bytes),ua_public_bytes)

det = det_orchid(raa, hda, ua_public_bytes)
#print("orchid", type(det),det)
detb = bytes(det, 'utf-8')
#print(type(detb),detb)
deti = int(bytes(det, 'utf-8'),16)
#print(type(deti),deti)

ua_hihex = ua_public_bytes.hex()

# Create Endorsement

elementb = datetime.datetime.strptime(vnb.strip(),"%m/%d/%Y")
tuple = elementb.timetuple()
vnbtime = time.mktime(tuple)
#print(type(vnbtime), vnbtime)
vnbh = hex(int(vnbtime))[2:]
#print(vnb, len(vnbh), vnbh)

elementa = datetime.datetime.strptime(vna.strip(),"%m/%d/%Y")
tuple = elementa.timetuple()
vnatime = time.mktime(tuple)
#print(vna, hex(int(vnatime))[2:].zfill(8))

pleasesign = hex(int(vnbtime))[2:].zfill(8) + hex(int(vnatime))[2:].zfill(8) + det.zfill(32) + ua_hihex.zfill(64) + DETofHDA
#print(pleasesign)
pleasesignb = bytes(pleasesign, 'utf-8')
#print(type(pleasesignb),pleasesignb)
signature = hda_prkey.sign(pleasesignb)
#print(type(signature.hex()),signature.hex())

endorsement = pleasesign + signature.hex()
print("UA Endorsement by HDA(", len(endorsement)/2, " bytes):" , endorsement)

#need to convert endorsement to bytes?
#with open("UA1endor.ment", "wb") as f:
#	f.write(endorsement)

ua_subject_sn = ua_csr.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
print("UA SN:",ua_subject_sn)

# Create X.509 cert

builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([]))
builder = builder.not_valid_before(elementb + datetime.timedelta(minutes=1))
builder = builder.not_valid_after(elementa + datetime.timedelta(hours=23, minutes=59))
# If HDA does not use CRL, can use short cert.serial_number
builder = builder.serial_number(random.randint(1000,9999))
# If HDA does use CRL, should use large cert.serial_number
#builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(ua_csr_pbkey)
builder = builder.add_extension(
	x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv6Address(deti))
#	,x509.UniformResourceIdentifier('https://cryptography.io')
	]),critical=True,)
builder = builder.issuer_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (DETofHDA + "I"))]))
certificate = builder.sign(hda_prkey, None)

with open("UA1.pem", "wb") as f:
	f.write(certificate.public_bytes(serialization.Encoding.PEM))

