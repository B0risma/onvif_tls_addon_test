from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from certTest import *
from keyTest import *
import base64
# older cert
#inter1
CERT_1 = '''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'''
CERT_3 = '''MIIFJDCCAwygAwIBAgIUHa4HIdr+KgS/yiybAG8pg3A1990wDQYJKoZIhvcNAQELBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRMwEQYDVQQKDApNeSBDb21wYW55MRowGAYDVQQLDBFJbnRlcm1lZGlhdGUgQ0EgMjElMCMGA1UEAwwcTXkgQ29tcGFueSBJbnRlcm1lZGlhdGUgQ0EgMjAeFw0yNTEyMDUxMDIyNDNaFw0yNjEyMDUxMDIyNDNaMIGAMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEGA1UECgwKTXkgQ29tcGFueTEVMBMGA1UECwwMV2ViIFNlcnZpY2VzMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtD+zvSO1XQr/BDUqkS+KYnbXlii9FjpcQzGMWnJ/LZQtjlHjxHSuRl25+eyyZ6TK6co/jPPF6F2Y5LCkXFvaNJLRpxd/rxC/11qZiq46pCTmTlCsVEIzmEv+fNYms2GnFJDvBG2EmzCYW8SMUmGFV7Y/R9XY99sKiIC5kvVbf7SKr6cEp/GqBqpNOXFY/ydhNieoTSZYmKmQsv2y+cNGxnEHYsvZ8BB+Hd4UPc3fVR/nFxB4o6M/JZVnJnPo0VaW6RqWj9dyeCqKOzBoE++eowUtHcMSbAxX7wxpKVg4770ocFrrz9AzkVGz40ieO2wBp9RySrRM9N2/i+b4yp7ehAgMBAAGjgYEwfzAdBgNVHQ4EFgQUV5dfib/2tvpX3OYhVgwknd/S7rIwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCcGA1UdEQQgMB6CD3d3dy5leGFtcGxlLmNvbYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggIBAAB24+phmRftfo9LxqY76ZYJINbXs4pRrBCvYLRC4SSHmt5UWFmMy6n16eXbtDCK22zc5TMKsl/xWl2wtZUKfQwAsXN/IaPUTUrObC/OJhpV1EMLWLzCaPXI1ZwPQhe5TChtblHdm70V68d6ZULnWNnhyYsIM6MXUoGaXYNmAKDTl3nhBeKPhB0PkOMeYXnaYoQwAD521jLNipyEj2S7g2dlTcRu0s72ZwAaM65DcM7ZJ46j9AWDQHvf3H6+WXd4luQwMs32juodLPU/YTQHQuCNOo4EMJDZwtVA3DvVSjW9U1QtBBuIvS4CfD6IdD1kZS9Glgfm2oN/pf0UBK3SxjyFZd57yNg9Xe55fEFdA8742i+jQhnyMcU9WbH9agssTDcxFMeUq8jVBM20TiRU4HjMU0SgKFlOAzUbQgVtLbmyNCrzMe3yMSw07T1eTVhDowHSqQsatN7dZh9kkpMHtzSWyz4eyPcww9vE4kvUqTG2kn5AdedPZtaFtAMEuZELp8sQNyax01Thw7GTXklVB4C2iUU3vkAWBM27zWPfQJxkzaGGx0yZkMXFQSyd0zUzf78fAoYKUOwSmHnR9AnFMpaSMpU6ImBo9xBTMKsvkbKB5S5C0Baw3SgQRg3JNtXWkSXbeCfRYV/jQp8svei64P6C1OoupksgQ5/hxSVOjn2+'''






class PolicyTest:
    TEST_ALIAS = "TSET"

    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)
        self.keyLoader = KeyTest(ip, user, pwd)
        self.certLoader = CertTest(ip, user, pwd)

    def find(id : str, objs : list):
        obj = None
        for p in objs:
            if p['CertPathValidationPolicyID'] == id:
                obj = p
                break
        return obj
    
    def createCertArgs(certIds:list, alias:str = TEST_ALIAS, id:str = None ):
        arg =  {
                # 'CertPathValidationPolicyID' : id,
                'Parameters' : {},
                'Alias' : alias,
        }
        if(len(certIds)):
            arg['TrustAnchor'] = []
        for i in certIds:
            arg['TrustAnchor'].append({'CertificateID' : i})

        if(id):
            arg['CertPathValidationPolicyID'] = id
        return arg
    
    def clean(self):
        self.keyLoader.clean()
        self.certLoader.clean()
        objs = self.keystore.GetAllCertPathValidationPolicies()
        print(objs)
        for obj in objs:
            id = obj['CertPathValidationPolicyID']
            self.keystore.DeleteCertPathValidationPolicy(id)
    
    def loadPolicy(self, certIds : list):
        args = PolicyTest.createCertArgs(certIds)
        print(f'toLoad:{args}')
        return self.keystore.CreateCertPathValidationPolicy(**args)
    
    def unpackTrustList(trustL):
        addedIds = []
        for id in trustL:
            addedIds.append(id['CertificateID'])
        print(f'TrustL: {addedIds}')
        return addedIds

    def uploadTest(self):
        self.clean()
        print('Loading policy + existed cert', end = '')
        certIds = [self.certLoader.uploadCert(CERT_1)['CertificateID']]
        objId = self.loadPolicy(certIds)
        objs = self.keystore.GetAllCertPathValidationPolicies()
        obj = PolicyTest.find(objId, objs)
        print(f"{obj}")
        if(not obj):
            raise ValueError("certPolicy doesn`t exist")
        if certIds != PolicyTest.unpackTrustList(obj['TrustAnchor']):
            raise ValueError("invalid certIds")
        self.clean()
        print('OK')

        print('Loading policy + existed cert + not existed', end = '')
        certIds = [self.certLoader.uploadCert(CERT_1)['CertificateID'], "invalid"]
        obj = None
        try:
            obj = self.loadPolicy(certIds)
        except Fault as e:
            #normal
            pass
        if(obj):
            raise ValueError("policy with unexisted certID loaded!")
        self.clean()
        print('OK')

        print('Loading policy + 2 existed cert', end = '')
        certIds = [self.certLoader.uploadCert(CERT_1)['CertificateID'], self.certLoader.uploadCert(CERT_1)['CertificateID']]
        objId = self.loadPolicy(certIds)
        objs = self.keystore.GetAllCertPathValidationPolicies()
        obj = PolicyTest.find( objId, objs)
        print(obj)
        if(not obj):
            raise ValueError("certPolicy doesn`t exist")
        if certIds != PolicyTest.unpackTrustList(obj['TrustAnchor']):
            raise ValueError("invalid certIds")
        self.clean()
        print('OK')

        # zeep dont allow empty list!
        # print("Loading empty trustAnchor list", end = '') # <- must be OK for reseting default policy
        # obj = None
        # try:
        #     obj = self.loadPolicy([])
        # except Fault as e:
        #     #normal
        #     pass
        # if(obj):
        #     raise ValueError('empty trusted list LOADED!')
        # self.clean()
        # print('OK')
        print("UploadTest passed!")

    def limitTest(self):
        self.clean()
        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        limit = caps['KeystoreCapabilities']['MaximumNumberOfCertificationPathValidationPolicies']
        print(f'Policy limit {limit}: ', end='')
        status = False
        certIds = [self.certLoader.uploadCert(CERT_1)['CertificateID']]
        for i in range(0, limit):
            status = self.loadPolicy(certIds)
        
        status = False
        try:
            # overflow
            status = self.loadPolicy(certIds)
        except Fault as e:
            #normal
            pass
        # alternative handling
        if(status):
            raise ValueError("no upload limit")
        self.clean()
        print('OK')
        print('LimitTest passed!')

    def test(self):
        print('********POLICY**********')
        self.clean()
        objs = self.keystore.GetAllCertPathValidationPolicies()
        # print(objs)
        if len(objs):
            raise ValueError("Cant delete pathes`")
        self.uploadTest() 
        # setTest
        self.limitTest()
        self.clean()
        print(f'PolicyTest passed!')