from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from certTest import *
from keyTest import *
import base64
# older cert
#inter1
CERT_1 = '''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'''
#inter2
CERT_2 = '''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'''
# younger cert
CERT_3 = '''MIIFJDCCAwygAwIBAgIUHa4HIdr+KgS/yiybAG8pg3A1990wDQYJKoZIhvcNAQELBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRMwEQYDVQQKDApNeSBDb21wYW55MRowGAYDVQQLDBFJbnRlcm1lZGlhdGUgQ0EgMjElMCMGA1UEAwwcTXkgQ29tcGFueSBJbnRlcm1lZGlhdGUgQ0EgMjAeFw0yNTEyMDUxMDIyNDNaFw0yNjEyMDUxMDIyNDNaMIGAMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEGA1UECgwKTXkgQ29tcGFueTEVMBMGA1UECwwMV2ViIFNlcnZpY2VzMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtD+zvSO1XQr/BDUqkS+KYnbXlii9FjpcQzGMWnJ/LZQtjlHjxHSuRl25+eyyZ6TK6co/jPPF6F2Y5LCkXFvaNJLRpxd/rxC/11qZiq46pCTmTlCsVEIzmEv+fNYms2GnFJDvBG2EmzCYW8SMUmGFV7Y/R9XY99sKiIC5kvVbf7SKr6cEp/GqBqpNOXFY/ydhNieoTSZYmKmQsv2y+cNGxnEHYsvZ8BB+Hd4UPc3fVR/nFxB4o6M/JZVnJnPo0VaW6RqWj9dyeCqKOzBoE++eowUtHcMSbAxX7wxpKVg4770ocFrrz9AzkVGz40ieO2wBp9RySrRM9N2/i+b4yp7ehAgMBAAGjgYEwfzAdBgNVHQ4EFgQUV5dfib/2tvpX3OYhVgwknd/S7rIwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCcGA1UdEQQgMB6CD3d3dy5leGFtcGxlLmNvbYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggIBAAB24+phmRftfo9LxqY76ZYJINbXs4pRrBCvYLRC4SSHmt5UWFmMy6n16eXbtDCK22zc5TMKsl/xWl2wtZUKfQwAsXN/IaPUTUrObC/OJhpV1EMLWLzCaPXI1ZwPQhe5TChtblHdm70V68d6ZULnWNnhyYsIM6MXUoGaXYNmAKDTl3nhBeKPhB0PkOMeYXnaYoQwAD521jLNipyEj2S7g2dlTcRu0s72ZwAaM65DcM7ZJ46j9AWDQHvf3H6+WXd4luQwMs32juodLPU/YTQHQuCNOo4EMJDZwtVA3DvVSjW9U1QtBBuIvS4CfD6IdD1kZS9Glgfm2oN/pf0UBK3SxjyFZd57yNg9Xe55fEFdA8742i+jQhnyMcU9WbH9agssTDcxFMeUq8jVBM20TiRU4HjMU0SgKFlOAzUbQgVtLbmyNCrzMe3yMSw07T1eTVhDowHSqQsatN7dZh9kkpMHtzSWyz4eyPcww9vE4kvUqTG2kn5AdedPZtaFtAMEuZELp8sQNyax01Thw7GTXklVB4C2iUU3vkAWBM27zWPfQJxkzaGGx0yZkMXFQSyd0zUzf78fAoYKUOwSmHnR9AnFMpaSMpU6ImBo9xBTMKsvkbKB5S5C0Baw3SgQRg3JNtXWkSXbeCfRYV/jQp8svei64P6C1OoupksgQ5/hxSVOjn2+'''

VALID_ORDER = [CERT_2, CERT_1]
INVALID_ORDER = [CERT_1, CERT_2]

class PathTest:
    TEST_ALIAS = "TSET"

    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)

        self.certLoader = CertTest(ip, user, pwd)
        self.keyLoader = KeyTest(ip, user, pwd)

    def find(id : str, objs : list, Alias:str = None):
        obj = None
        for p in objs:
            if p['CertificationPathID'] == id:
                obj = p
                break
        if Alias and obj and obj['Alias'] != Alias:
            print(f'Unexpected Alias: {obj['Alias']} must be {Alias}')
        return obj
    
    
    def clean(self):
        self.keyLoader.clean()
        self.certLoader.clean()
        objs = self.keystore.GetAllCertificationPaths()
        # print(objs)
        for p in objs:
            self.keystore.DeleteCertificationPath(p)
    # [child cert .... parent cert]
    def createCertPath(self, list_b64_der : list):
        idL = []
        try:
            for crt in list_b64_der:
                idL.append(self.certLoader.uploadCert(crt)['CertificateID'])
        except Fault as e:
            print(e)
            raise ValueError(f"Cant load certificate (loaded: {idL})")
        # print(f"certPath to upload: {idL}")
        arg = {'CertificateIDs' : {
            'CertificateID' : idL
        }}
        return self.keystore.CreateCertificationPath(**arg)
    
    def uploadTest(self):
        self.clean()
        print("loading path (size 2): ", end = '')
        path_id = self.createCertPath(VALID_ORDER)
        if path_id == INVALID_ID:
            raise ValueError("cant create valid path")
        print("OK")
        self.clean()
       
        print("loading invalid ordered path: ", end = '')
        path_id = None
        try:
            path_id = self.createCertPath(INVALID_ORDER)
        except Fault as e:
            #normal
            pass
        if path_id and path_id != INVALID_ID:
            raise ValueError("unordered path created")
        print("OK")

        print("loading path (size 3): ", end = '')
        path_id = self.createCertPath([CERT_3, CERT_2, CERT_1])
        if path_id == INVALID_ID:
            raise ValueError("cant create valid path")
        print("OK")

    def multiLoadTest(self):
        self.clean()
        print("loading path multiple times: ", end = '')
        for i in range(0,10):
            path_id = self.createCertPath(VALID_ORDER)
            if path_id == INVALID_ID:
                raise ValueError("cant create valid path")
            print("OK", end=' ')
            # print("Clean")
            self.clean()
        print("",)

    def limitTest(self):
        self.clean()

        idL = []
        for crt in VALID_ORDER:
            idL.append(self.certLoader.uploadCert(crt)['CertificateID'])
        
        arg = {'CertificateIDs' : {
            'CertificateID' : idL
        }}

        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        limit = caps['KeystoreCapabilities']['MaximumNumberOfCertificationPaths']
        print(f'Paths limit {limit}: ', end='')
        
        for i in range(0, limit):
            obj = self.keystore.CreateCertificationPath(**arg)
            if(obj == INVALID_ID):
                raise ValueError(f"Cant create {i} path")
        
        obj = None
        try:
            # overflow
            obj = self.createCertPath(VALID_ORDER)
        except Fault as e:
            #normal
            pass
        # alternative handling
        if(obj and obj != INVALID_ID):
            raise ValueError("no upload limit")
        self.clean()
        print('OK')
        print('PathLimitTest passed!')

    def test(self):
        print('********PATH**********')
        self.clean()
        objs = self.keystore.GetAllCertificationPaths()
        # print(objs)
        if len(objs):
            raise ValueError("Cant delete pathes`")

        self.uploadTest() 
        self.multiLoadTest()       
        self.limitTest()
        self.clean()
        print(f'PathTest passed!')