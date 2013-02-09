## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
TLS Transport Layer Security RFCs 2246, 4366, 4507

Spencer McIntyre
SecureState R&D Team
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.l2 import *

# http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-3
cipher_suites = {
        0x0000:"TLS_NULL_WITH_NULL_NULL",
        0x0001:"TLS_RSA_WITH_NULL_MD5",
        0x0002:"TLS_RSA_WITH_NULL_SHA",
        0x0003:"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004:"TLS_RSA_WITH_RC4_128_MD5",
        0x0005:"TLS_RSA_WITH_RC4_128_SHA",
        0x0006:"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0007:"TLS_RSA_WITH_IDEA_CBC_SHA",
        0x0008:"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0009:"TLS_RSA_WITH_DES_CBC_SHA",
        0x000a:"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0011:"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0012:"TLS_DHE_DSS_WITH_DES_CBC_SHA",
        0x0013:"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        0x0014:"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0015:"TLS_DHE_RSA_WITH_DES_CBC_SHA",
        0x0016:"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0017:"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        0x002f:"TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0032:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        0x0033:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0034:"TLS_DH_anon_WITH_AES_128_CBC_SHA",
        0x0035:"TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0038:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        0x0039:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0041:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0044:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        0x0045:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0062:"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        0x0063:"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        0x0064:"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        0x0084:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0087:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        0x0088:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0089:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        0x0096:"TLS_RSA_WITH_SEED_CBC_SHA",
        0x0099:"TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        0x009a:"TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        0x00ff:"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    }

tls_handshake_types = {
        0:"HELLO REQUEST",
        1:"CLIENT HELLO",
        2:"SERVER HELLO",
        11:"CERTIFICATE",
        12:"SERVER KEY EXCHANGE",
        13:"CERTIFICATE REQUEST",
        14:"SERVER HELLO DONE",
        15:"CERTIFICATE VERIFY",
        16:"CLIENT KEY EXCHANGE",
        20:"FINISHED"
    }
    
tls_compression_methods = {
        0:"NONE",
        1:"DEFLATE",
        64:"LZS"
    }

class TLSv1RecordLayer(Packet):
    name = "TLSv1 Record Layer"
    fields_desc = [ ByteEnumField("code", 22, {20:"CHANGE CIPHER SPEC", 21:"ALERT", 22:"HANDSHAKE", 23:"APPLICATION DATA"}),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1), 
                    FieldLenField("length", None, length_of="data", fmt="H"),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length), lambda pkt:pkt.code != 22),
                    ConditionalField(ByteEnumField("hs_type", 1, tls_handshake_types), lambda pkt:pkt.code == 22),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length - 1), lambda pkt:pkt.code == 22 and pkt.hs_type not in tls_handshake_types),
                ]
                
    def guess_payload_class(self, payload):
        if self.code != 22:
            return TLSv1RecordLayer
        elif self.hs_type in [1, 2, 11, 12, 14, 16]:
            return {1:TLSv1ClientHello, 2:TLSv1ServerHello, 11:TLSv1Certificate, 12:TLSv1KeyExchange, 14:TLSv1ServerHelloDone, 16:TLSv1KeyExchange}[self.hs_type]
        else:
            return TLSv1RecordLayer

class TLSv1ClientHello(Packet):
    name = "TLSv1 Client Hello"
    fields_desc = [ FieldThreeBytesLenField("length", 36, adjust=lambda pkt, x:pkt.session_id_length + pkt.cipher_suites_length + pkt.compression_methods_length + 36),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    
                    FieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                    ConditionalField(StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length), lambda pkt:pkt.session_id_length),
                    
                    FieldLenField("cipher_suites_length", 2, length_of="cipher_suites", fmt="H"),
                    FieldListField("cipher_suites", [0x0000], ShortEnumField("cipher_suite", 0x0000, cipher_suites), count_from = lambda pkt:pkt.cipher_suites_length / 2),
                    
                    FieldLenField("compression_methods_length", 1, length_of="compression_methods", fmt="B"),
                    FieldListField("compression_methods", [0x00], ByteEnumField("compression_method", 0x00, tls_compression_methods), count_from = lambda pkt:pkt.compression_methods_length),
                    
                    ConditionalField(FieldLenField("extensions_length", 2, length_of="extensions", fmt="H"), lambda pkt:pkt.length > pkt.session_id_length + pkt.cipher_suites_length + pkt.compression_methods_length + 36),
                    ConditionalField(StrLenField("extensions", "", length_from=lambda pkt:pkt.extensions_length), lambda pkt:pkt.extensions_length),
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHello(Packet):
    name = "TLSv1 Server Hello"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of=lambda pkt:pkt.session_id_length + 40),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    FieldLenField("session_id_length", 0, length_of="session_id", fmt="B"),
                    ConditionalField(StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length), lambda pkt:pkt.session_id_length),
                    ShortEnumField("cipher_suite", 0x0000, cipher_suites),
                    ByteEnumField("compression_method", 0x00, {0x00:"NONE"}),
                    
                    ConditionalField(FieldLenField("extensions_length", 0, length_of="extensions", fmt="H"), lambda pkt:pkt.length > pkt.session_id_length + 38),
                    ConditionalField(StrLenField("extensions", "", length_from=lambda pkt:pkt.extensions_length), lambda pkt:pkt.extensions_length),
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHelloDone(Packet):
    name = "TLSv1 Server Hello Done"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="server_cert", adjust=lambda pkt,x:len(pkt.data) + 2),
                    StrLenField("data", "", length_from=lambda pkt: pkt.length)
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer

class TLSv1KeyExchange(Packet):
    name = "TLSv1 Key Exchange"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="server_cert"),
                    StrLenField("server_cert", "", length_from=lambda pkt:pkt.length),
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1Certificate(Packet):
    name = "TLSv1 Certificate"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="certificate"),
                    StrLenField("certificate", "", length_from=lambda pkt:pkt.length),
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
