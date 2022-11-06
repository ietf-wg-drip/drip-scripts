import json
from enum import Enum
from nacl.signing import SigningKey
from nacl.encoding import Base16Encoder, Base64Encoder
import datetime

import typing as t

import textwrap

KEY = bytes("xhCmfvPg5hUPizDcV2w6XPxD8mMlOh2d", 'ascii') # test key, no meaning

class SignatureType(Enum):
    ED25519 = 0

def sign(
    key: bytes,
    type: SignatureType,
    message: bytes):
    
    if type != SignatureType.ED25519:
        raise Exception("unsupported signature type")
    
    signingKey = SigningKey(key)
    signature = signingKey.sign(message).signature

    b16 = Base16Encoder.encode(signature).decode()
    b64 = Base64Encoder.encode(signature).decode()

    return (signature, b16, b64)

class EndorsementType(Enum):
    GENERIC = 0
    """
    ## Endorsement (E-x.y)

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET of X", "hi_b16": "base16 HI of X"}`` \n
     - evidence -- ``[Self-Endorsement (SE-x) instance]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """
    SELF = 1
    """
    ## Self-Endorsement (SE-x)

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET"}`` \n
     - evidence -- ``[base16 host identity]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """
    CONCISE = 2
    """
    ## Concise Endorsement (CE-x.y)

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET of X"}`` \n
     - evidence -- ``[base16 HHIT/DET of Y]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """
    MUTUAL = 3
    """
    ## Mutual Endorsement (ME-x.y)

    An endorsement that perform a sign over an existing Endorsement where 
    the signer is the second party of the embedded endorsement.
    The DET of party Y is used as the identity.

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET of Y"}`` \n
     - evidence -- ``[Endorsement (E-x.y) instance]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """
    LINK = 4
    """
    ## Link Endorsement (LE-x.y)

    An endorsement that perform a sign over an existing Concise Endorsement where
    the signer is the second party of the embedded endorsement. The DET of party Y is used as the identity.

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET of Y"}`` \n
     - evidence -- ``[Concise Endorsement (CE-x.y) instance]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """
    BROADCAST = 5
    """
    ## Broadcast Endorsement (BE-x.y)

    ### Keyword arguments:
     - identity -- ``{"hhit": "base16 HHIT/DET of X"}`` \n
     - evidence -- ``["base16 HHIT/DET of Y", "base16 HI of Y"]`` \n
     - scope -- ``{"vnb": utc_timestamp_int, "vna": utc_timestamp_int}`` \n
    """

class EndorsementKeyException(Exception):
    """
    An endorsement could not be produced as the required properties were missing on the class instance / dict
    """
    pass

class EndorsementSerializationException(Exception):
    """
    Serializing the endorsement from bytes has failed
    """
    pass

def hex_str_to_bytes(to_encode: str) -> bytes:
    return bytes.fromhex(to_encode)

def int_to_bytes(to_encode: int) -> bytes:
    return to_encode.to_bytes(4, byteorder="little")

def bytes_to_int(int_bytes: bytes) -> int:
    return int.from_bytes(int_bytes, byteorder='little')

def combine_bytes(byte_strings: list) -> bytes:
    return b''.join(byte_strings)
 
class Endorsement:
    def __init__(
        self,
        type: EndorsementType = EndorsementType.SELF,
        identity = None,
        evidence = None,
        scope = None,
        signature = None,
        bytes_data: t.Optional[bytes] = None,
        signature_data: t.Optional[bytes] = None
    ):
        self.__bytes_data = bytes_data
        self.__signature_data = signature_data

        self.type = type
        self.identity = {} if identity is None else identity
        self.evidence = [] if evidence is None else evidence
        self.scope = {} if scope is None else scope
        self.signature = {} if signature is None else signature

    def __repr__(self):
        def __wrap(txt):
            return '\n'.join(
                textwrap.wrap(txt, width=80)
            )

        def __cert_valid():
            return '\033[92mVALID\033[0m' \
                if int(datetime.datetime.utcnow().timestamp()) > int(self.scope['vnb']) \
                and int(datetime.datetime.utcnow().timestamp()) < int(self.scope['vna']) \
                else '\033[91mINVALID\033[0m'

        return f"""
================================================================================
================================================================================
                              class Endorsement
================================================================================
Type: {self.type.name}
================================================================================
Identity:
{__wrap(str(self.identity))}
================================================================================
Evidence:
{__wrap(str(self.evidence) if len(self.evidence) and isinstance(self.evidence[0], str) else '')}{__wrap(str([self.evidence[0].toBytes().hex()]) if len(self.evidence) and isinstance(self.evidence[0], Endorsement) else '')}
================================================================================
Scope:
Valid not Before: {datetime.datetime.fromtimestamp(self.scope['vnb'])}
Valid not After: {datetime.datetime.fromtimestamp(self.scope['vna'])}
{__cert_valid()}
================================================================================
Signature:
{__wrap(str(self.signature))}
================================================================================
================================================================================
"""
    
    def __getEvidence(self, hex=True):
        if hex == False and isinstance(self.evidence[0], Endorsement):
            return self.evidence[0]

        evidence_item_bytes = []
        for evidence_item in self.evidence:
            if isinstance(evidence_item, Endorsement):
                evidence_item_bytes.append(
                    hex_str_to_bytes(evidence_item.toBytes().hex())
                )
            elif isinstance(evidence_item, str):
                evidence_item_bytes.append(
                    hex_str_to_bytes(evidence_item)
                )

        return combine_bytes(evidence_item_bytes).hex()
    
    def toSignatureData(self) -> bytes:
        """
        Returns data that will be used to sign the endorsement (in bytes)
        """
        try:
            if 'vnb' not in self.scope or 'vna' not in self.scope:
                raise EndorsementKeyException('The Endorsment object\'s scope property is missing "vnb" or "vna" keys.')

            if 'hhit' not in self.identity:
                raise EndorsementKeyException('The Endorsement object\'s identity property is missing the "hhit" key.')

            if len(self.evidence) < 1:
                raise EndorsementKeyException('The Endorsement object\'s evidence property has no items.')

            if self.type in {EndorsementType.SELF, EndorsementType.CONCISE, EndorsementType.MUTUAL, EndorsementType.LINK, EndorsementType.BROADCAST}:
                data = combine_bytes([
                    hex_str_to_bytes(self.identity["hhit"]),
                    hex_str_to_bytes(self.__getEvidence()),
                    int_to_bytes(self.scope["vnb"]),
                    int_to_bytes(self.scope["vna"])
                ])

                self.__bytes_data = data

                return data

            elif self.type == EndorsementType.GENERIC:
                if 'hi_b16' not in self.identity:
                    raise EndorsementKeyException('The Endorsement object\'s identity property is missing the "hi_b16" key.')
                
                data = combine_bytes([
                    hex_str_to_bytes(self.identity["hhit"]),
                    hex_str_to_bytes(self.identity["hi_b16"]),
                    hex_str_to_bytes(self.__getEvidence()),
                    int_to_bytes(self.scope["vnb"]),
                    int_to_bytes(self.scope["vna"])
                ])

                self.__bytes_data = data

                return data
            
        except EndorsementKeyException as e:
            raise e

        return combine_bytes([])
    
    def toJSON(self) -> str:
        excluded_properties = {'type', '_Endorsement__bytes_data', '_Endorsement__signature_data'}
        return json.dumps({
            dict_key: self.__dict__[dict_key] for dict_key in self.__dict__ if dict_key not in excluded_properties
        })

    def sign(self, key: bytes, signature_type: SignatureType):
        sig, b16, b64 = sign(key, signature_type, self.toSignatureData())
        self.__signature_data = sig
        self.signature = {"sig_b16": b16}

    def toBytes(self) -> bytes:
        return combine_bytes([self.__bytes_data, self.__signature_data])

    @classmethod
    def fromBytes(cls, type: EndorsementType, bytes_obj: bytes):
        if type == EndorsementType.SELF:
            entity_tag = bytes_obj[:16]
            host_identity = bytes_obj[16:48]
            vnb = bytes_obj[48:52]
            vna = bytes_obj[52:56]
            signature = bytes_obj[56:]

            return Endorsement(
                type,
                identity={'hhit': entity_tag.hex()},
                evidence=[ host_identity.hex() ],
                scope={ 'vnb': bytes_to_int(vnb), 'vna': bytes_to_int(vna) },
                signature={ 'sig_b16': signature.hex() },
                bytes_data=combine_bytes([entity_tag, host_identity, vnb, vna]),
                signature_data=signature
            )

        elif type == EndorsementType.GENERIC:
            entity_tag = bytes_obj[:16]
            entity_tag_hi_b16 = bytes_obj[16:48]
            self_endorsement = bytes_obj[48:168] # this does not really have a fixed length so TODO
            # will need to look at first bytes of the blob to check what encryption was used
            # and padding can be accounted for then
            vnb = bytes_obj[168:172]
            vna = bytes_obj[172:176]
            signature = bytes_obj[176:]
            
            return Endorsement(
                type,
                identity={'hhit': entity_tag.hex(), 'hi_b16': entity_tag_hi_b16.hex() },
                evidence=[ self_endorsement.hex() ],
                scope={ 'vnb': bytes_to_int(vnb), 'vna': bytes_to_int(vna) },
                signature={ 'sig_b16': signature.hex() },
                bytes_data=combine_bytes([entity_tag, self_endorsement, vnb, vna]),
                signature_data=signature
            )

        elif type == EndorsementType.CONCISE:
            entity_tag = bytes_obj[:16]
            entity_tag_2 = bytes_obj[16:32]
            vnb = bytes_obj[32:36]
            vna = bytes_obj[36:40]
            signature = bytes_obj[40:]

            return Endorsement(
                type,
                identity={'hhit': entity_tag.hex()},
                evidence=[ entity_tag_2.hex() ],
                scope={ 'vnb': bytes_to_int(vnb), 'vna': bytes_to_int(vna) },
                signature={ 'sig_b16': signature.hex() },
                bytes_data=combine_bytes([entity_tag, entity_tag_2, vnb, vna]),
                signature_data=signature
            )

        elif type == EndorsementType.MUTUAL:
            entity_tag = bytes_obj[:16]
            endorsement = bytes_obj[16:256]
            vnb = bytes_obj[256:260]
            vna = bytes_obj[260:264]
            signature = bytes_obj[264:]

            return Endorsement(
                type,
                identity={'hhit': entity_tag.hex()},
                evidence=[ endorsement.hex() ],
                scope={ 'vnb': bytes_to_int(vnb), 'vna': bytes_to_int(vna) },
                signature={ 'sig_b16': signature.hex() },
                bytes_data=combine_bytes([entity_tag, endorsement, vnb, vna]),
                signature_data=signature
            )

        elif type == EndorsementType.LINK:
            entity_tag = bytes_obj[:16]
            concise_endorsement = bytes_obj[16:120]
            vnb = bytes_obj[120:124]
            vna = bytes_obj[124:128]
            signature = bytes_obj[128:]

            return Endorsement(
                type=type,
                identity={'hhit': entity_tag},
                evidence=[concise_endorsement.hex()],
                scope={ 'vnb': bytes_to_int(vnb), 'vna': bytes_to_int(vna) },
                signature={ 'sig_b16': signature.hex() },
                bytes_data=combine_bytes([entity_tag, concise_endorsement, vnb, vna]),
                signature_data=signature
            )

        elif type == EndorsementType.BROADCAST:
            entity_tag = bytes_obj[:16]
            entity_tag2 = bytes_obj[16:32]
            host_identity = bytes_obj[32:64]
            vnb = bytes_obj[64:68]
            vna = bytes_obj[68:72]
            signature = bytes_obj[72:]


            

if __name__ == '__main__':
    self_endorsement = Endorsement(
        EndorsementType.SELF,
        identity={"hhit": "2001003000000005ffffffffffffffff"},
        evidence=["abcdefabcdefabcdefabcdefabcdef01abcdefabcdefabcdefabcdefabcdef01"],
        scope={"vnb": int(datetime.datetime(2021, 1, 1).timestamp()), "vna": int(datetime.datetime(2023, 1, 1).timestamp())}
    )
    self_endorsement.sign(KEY, SignatureType.ED25519)
    # print("SELF")
    # print(self_endorsement.toBytes().hex())
    # print(self_endorsement)


    # second_self_end = Endorsement.fromBytes(EndorsementType.SELF, self_endorsement.toBytes())
    # if second_self_end:
    #     print(second_self_end)

    generic_end = Endorsement(
        EndorsementType.GENERIC,
        identity={ "hhit": "2001003000000005ffffffffffffffff", "hi_b16": "2001003000000005ffffffffffffffff2001003000000005ffffffffffffffff" },
        evidence=[ self_endorsement ],
        scope={"vnb": int(datetime.datetime.now().timestamp()), "vna": int(datetime.datetime.now().timestamp())}
    )
    generic_end.sign(KEY, SignatureType.ED25519)
    
    # print("GENERIC")
    # print(generic_end.toBytes().hex())
    # print(generic_end)

    second_generic = Endorsement.fromBytes(
        EndorsementType.GENERIC,
        generic_end.toBytes()
    )

    # print(second_generic)

    mutual_endorsement = Endorsement(
        type=EndorsementType.MUTUAL,
        identity={"hhit": "2001003000000005ffffffffffffffff"},
        evidence=[generic_end],
        scope={"vnb": int(datetime.datetime.now().timestamp()), "vna": int(datetime.datetime.now().timestamp())}
    )
    mutual_endorsement.sign(KEY, SignatureType.ED25519)

    # print("MUTUAL")
    # print(mutual_endorsement.toBytes().hex())
    # print(mutual_endorsement)

    second_mutual = Endorsement.fromBytes(
        mutual_endorsement.type,
        mutual_endorsement.toBytes()
    )

    # print(second_mutual)

    concise_endorsement = Endorsement(
        EndorsementType.CONCISE,
        identity={"hhit": "2001003000000005ffffffffffffffff"},
        evidence=["abcdefabcdefabcdefabcdefabcdef01abcdefabcdefabcdefabcdefabcdef01"],
        scope={"vnb": int(datetime.datetime.now().timestamp()), "vna": int(datetime.datetime.now().timestamp())}
    )
    concise_endorsement.sign(KEY, SignatureType.ED25519)

    # print(concise_endorsement)

    concise_copy = Endorsement.fromBytes(
        concise_endorsement.type,
        concise_endorsement.toBytes()
    )

    # print(concise_copy)

    broadcast_endorsement = Endorsement(
        EndorsementType.BROADCAST,
        identity={"hhit": "2001003000000005ffffffffffffffff"},
        evidence=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bcdefabcdefabcdefabcdefabcdeffffabcdefabcdefabcdefabcdefabcdef01"],
        scope={"vnb": int(datetime.datetime.now().timestamp()), "vna": int(datetime.datetime.now().timestamp())}
    )
    broadcast_endorsement.sign(KEY, SignatureType.ED25519)

    print("BROADCAST")
    print(broadcast_endorsement.toBytes().hex())
    print(broadcast_endorsement)