#!/bin/python

# HTT Consulting, LLC
# Robert Moskowitz
# 2025-03-18

# developed with Fedora 41 using
# dnf install python3-pycryptodomex
# https://pycryptodome.readthedocs.io/en/v3.15.0/src/introduction.html
# Two manditory files and one optional file needed.

# First manditory file is a pem private key file of the CA/signer
#		File name is <something>prv.pem
#			Passwording this file is not yet implemented

# Second manditory file is a file of commands to set the various server variables
#	The file name is --serverdat=<something> on the command line
#		default is server.dat
#
# sample content is:
#
#raa = 16376
#hda = 16376 - HDA of server
#serialnumberbits = 7
#cakey="raa16376"
#LOA_str = "1.3.27.16.1.1.0.1"
#selfsign = False
#certsign = False - set to true to include in CA cert

# Optional file is a file of commands to set the various variables
#	The file name is --commandfile=<something> on the command line
#		default is ua.dat
#
# sample content is:
#
#hda = 16376 - HDA of client
#vnb="04/01/2024"
#vna="04/01/2025"
#clientcsr="hda16376-16376A"
#clientpem="hda16376-16376A"
#caname = "RAA-A-16376-16376"
#entitycert=True
# caname when entitycert=False

__version__ = '2025-03-18'

import sys, getopt
import ipaddress
import time
import datetime
import random
from binascii import *
import binascii
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509 import CertificatePolicies, PolicyInformation
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Cryptodome.Hash import cSHAKE128
# Cryptodome is the only source for cSHAKE

def det_orchid(raa, hda, suiteid, hi):
	# set some defaults
	# ORCHID PREFIX = 2001:30/28 = b0010 0000 0000 0001:0000 0000 0011/28
	# HID = RAA (always 14 bits) + HDA (always 14 bits) = 10 + 20 = b00 0000 0000 1010 + b00 0000 0000 0001 0100

	b_prefix = '0010000000000001000000000011' # RFC 9374 Section 8.2.1
#	h_prefix = '2001003'

	b_ogaid = f'{suiteid:08b}'
#	print(type(b_ogaid), b_ogaid)
#	bo_ogaid = '00000101' # suiteid of 5, RFC 9374 Section 8.2.2
	ContextID = unhexlify("00B5A69C795DF5D5F0087F56843F2C40")
#	print("ContextID", type(ContextID),ContextID)


	#format the HID from RAA and HDA
#	print("raa:", raa)
#	print("hda:", hda)
	b_hid = f'{raa:014b}' + f'{hda:014b}'
#	print("HID:", b_hid)

	# perform hash with cSHAKE using input data
	orchid_left = b_prefix + b_hid + b_ogaid
#	print("orchid_left", type(orchid_left), orchid_left)
#	hu_orchid_left = unhexlify(b_prefix + b_hid + b_ogaid)
	h_orchid_left = hex(int((b_prefix + b_hid + b_ogaid), 2))[2:]
#	print("h_orchid_left", type(h_orchid_left),h_orchid_left)
#	h_orchid_left = bytes(h_orchid_left, 'utf-8')
	h_orchid_left = bytes.fromhex(h_orchid_left)
#	h_orchid_left = unhexlify(b_prefix + b_hid + b_ogaid)
#	h_orchid_left = bytes.fromhex(h_orchid_left)

#	print("h_orchid_left.hex()", type(h_orchid_left.hex()), h_orchid_left.hex())
	shake =  cSHAKE128.new(custom = ContextID)
#	print("h_orchid_left", type(h_orchid_left),h_orchid_left)
#	print("hu_orchid_left", type(hu_orchid_left),hu_orchid_left)
#	print("hi",type(hi), hi)
	det_source = h_orchid_left + hi
#	print("det_source",type(det_source), det_source)
#	shake.update((hu_orchid_left + hi))
	shake.update(det_source)
	h_hash = shake.read(8).hex()
#	print(type(h_hash),h_hash)

	# format orchid in binary
	h_orchid = hex(int(b_prefix + b_hid + b_ogaid, 2))[2:] + h_hash
#	orchid = 2

	print("DET:", h_orchid)
	# add in ':' for IPv6
	str_orchid = ':'.join(h_orchid[i:i+4] for i in range(0, len(h_orchid), 4))
	print("DET:", str_orchid)

	return h_orchid

# If RAA does not use CRL, can use short cert.serial_number
# If RAA does use CRL, should use large cert.serial_number
commandfile = "client.dat"
serialnumberbits = 7
LOA_str = "1.3.27.16.1.1.0.1"
vnb = "04/01/2024"
vna = "04/01/2025"
clientcsr="hda1"
cakey="raa"
certsign = False
selfsign = False
entitycert = True

# will derive CA DET from RAA, HDA, etc.
raa = 16376
hda = 16376

try:
	opts, args = getopt.getopt(sys.argv[1:],"hn:p:c:",["serverdat=","commandfile="])
except getopt.GetoptError:
	print('Error')
	sys.ext(2)

#	parse the args
for opt, arg in opts:
	if opt == '-h':
		print('endorse.py --serverdat <Server commanddat> --commandfile <Client commandfile>')
		sys.exit()
	elif opt in ("-s", "--serverdat"):
		serverdat = arg + ".dat"
	elif opt in ("-c", "--commandfile"):
		commandfile = arg + ".dat"

file1 = open(commandfile, 'r')
a = True
while a:
	line = file1.readline()
#	print(line.strip())
	if not line:
		a = False
	exec("%s" % line.strip())
file1.close()
clhda = hda

# read serverfile after commandfile, so client cannot overright server vars
file2 = open(serverdat, 'r')
a = True
while a:
	line = file2.readline()
#	print(line.strip())
	if not line:
		a = False
	exec("%s" % line.strip())
file2.close()
cahda = hda

clientcsr=clientcsr + "csr.pem"
cakey=cakey + "prv.pem"

with open(cakey, "rb") as f:
	ca_pkkey = f.read()
f.close()

ca_prkey = load_pem_private_key(ca_pkkey, None)
ca_prkey_bytes = ca_prkey.private_bytes(
	encoding=serialization.Encoding.Raw,
	format=serialization.PrivateFormat.Raw,
	encryption_algorithm=serialization.NoEncryption()
	)
#print("pr", type(ca_prkey_bytes), ca_prkey_bytes)
ca_pukey = ca_prkey.public_key()
ca_pukey_bytes = ca_pukey.public_bytes(
	encoding=serialization.Encoding.Raw,
	format=serialization.PublicFormat.Raw
	)
#print("ca_hi",type(ca_pukey_bytes),ca_pukey_bytes)
#ca_hibytes = bytes(ca_pukey_bytes.hex(), 'utf-8')
#print("ca_hibytes",type(ca_hibytes),ca_hibytes)
print("CA")
#print(raa, cahda, suiteid)
#print("pu", type(ca_pukey_bytes), ca_pukey_bytes)
cadet = det_orchid(raa, cahda, suiteid, ca_pukey_bytes)
#cadet = det_orchid(raa, cahda, suiteid, ca_hibytes)
#print("ca orchid", type(cadet),cadet)

with open(clientcsr, "rb") as f:
	client_pem_req_data = f.read()
f.close()

client_csr = x509.load_pem_x509_csr(client_pem_req_data)
client_csr_pbkey = client_csr.public_key()
#print("x",client_csr_pbkey)
client_public_bytes = client_csr.public_key().public_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PublicFormat.Raw,)
#print("client_hi",type(client_public_bytes),client_public_bytes)
#client_hibytes = bytes(client_public_bytes.hex(), 'utf-8')
#print("client_hibytes",type(client_hibytes),client_hibytes)
print("Client")
clientdet = det_orchid(raa, cahda, suiteid, client_public_bytes)
#clientdet = det_orchid(raa, clhda, suiteid, client_hibytes)
#print("client orchid", type(clientdet),clientdet)

cldetb = bytes(clientdet, 'utf-8')
#print(type(cldetb),cldetb)
cldeti = int(bytes(clientdet, 'utf-8'),16)
#print(type(cldeti),cldeti)
client_hihex = client_public_bytes.hex()
print("Client HI:", client_hihex)

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

pleasesign = hex(int(vnbtime))[2:].zfill(8) + hex(int(vnatime))[2:].zfill(8) + clientdet.zfill(32) + client_hihex.zfill(64) + cadet
#print(pleasesign)
pleasesignb = bytes(pleasesign, 'utf-8')
#print(type(pleasesignb),pleasesignb)
signature = ca_prkey.sign(pleasesignb)
#print(type(signature.hex()),signature.hex())

endorsement = pleasesign + signature.hex()
print("Client Endorsement by CA(", len(endorsement)/2, " bytes):" , endorsement)

#need to convert endorsement to bytes?
with open(clientpem + ".eds", "w") as f:
	f.write(endorsement)

client_subject_sn = client_csr.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
print("client SN:",client_subject_sn)

# Create Lite X.509 cert

builder = x509.CertificateBuilder()
if entitycert:
	builder = builder.subject_name(x509.Name([]))
else:
	builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DRIP-" + caname)]))
	builder = builder.add_extension(
		x509.BasicConstraints(ca=True, path_length=None), critical=True,
		)
builder = builder.not_valid_before(elementb + datetime.timedelta(minutes=1))
builder = builder.not_valid_after(elementa + datetime.timedelta(hours=23, minutes=59))
builder = builder.serial_number(random.getrandbits(serialnumberbits))
builder = builder.public_key(client_csr_pbkey)
builder = builder.add_extension(
	x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv6Address(cldeti))
#	,x509.UniformResourceIdentifier('https://cryptography.io')
	]),critical=True,)
# need to fix this...

if certsign:
	builder = builder.add_extension(
		x509.KeyUsage(digital_signature=False, key_encipherment=False, content_commitment=False,
					data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False,
					encipher_only=False, decipher_only=False),
		critical=True,
)

builder = builder.issuer_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (cadet))]))
certificate = builder.sign(ca_prkey, None)

with open(clientpem + ".pem", "wb") as f:
	f.write(certificate.public_bytes(serialization.Encoding.PEM))

# Create PKIX X.509 cert

builder = x509.CertificateBuilder()
if entitycert:
	builder = builder.subject_name(x509.Name([]))
else:
	builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DRIP-" + caname)]))
	builder = builder.add_extension(
		x509.BasicConstraints(ca=True, path_length=None), critical=True,
		)
	policy_info = PolicyInformation(ObjectIdentifier(LOA_str), None)
	builder = builder.add_extension(
		CertificatePolicies([policy_info]), critical=False)
builder = builder.not_valid_before(elementb + datetime.timedelta(minutes=1))
builder = builder.not_valid_after(elementa + datetime.timedelta(hours=23, minutes=59))
# If HDA does not use CRL, can use short cert.serial_number
builder = builder.serial_number(random.getrandbits(serialnumberbits))
# If HDA does use CRL, should use large cert.serial_number
#builder = builder.serial_number(x509.random_serial_number())
builder = builder.public_key(client_csr_pbkey)
builder = builder.add_extension(
	x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv6Address(cldeti))
#	,x509.UniformResourceIdentifier('https://cryptography.io')
	]),critical=True,)
builder = builder.issuer_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (cadet))]))

# Create the Subject Key Identifier extension
#ski = x509.SubjectKeyIdentifier.from_public_key(sub_csr_pbkey)
if not entitycert:
	builder = builder.add_extension(
		x509.SubjectKeyIdentifier(binascii.unhexlify(clientdet)), critical=False)
if not selfsign:
	builder = builder.add_extension(
		x509.AuthorityKeyIdentifier(key_identifier=binascii.unhexlify(cadet), 
		authority_cert_issuer=None, authority_cert_serial_number=None), critical=False)

certificate = builder.sign(ca_prkey, None)

with open(clientpem + "pkix.pem", "wb") as f:
	f.write(certificate.public_bytes(serialization.Encoding.PEM))

