from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from keyTest import *
import base64

class CertTest:
    TEST_ALIAS = "TSET"
    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)
        self.keyLoader = KeyTest(ip, user, pwd)

    def find(id : str, certs : list, Alias:str = None):
        Certificate = None
        for p in certs:
            if p['CertificateID'] == id:
                Certificate = p
                break
        if Alias and Certificate and Certificate['Alias'] != Alias:
            print(f'Unexpected Alias: {Certificate['Alias']} must be {Alias}')
        return Certificate
    
    def clean(self):
        self.keyLoader.clean()
        objs = self.keystore.GetAllCertificates()
        # print(f'current passes: {pwds}')
        for p in objs:
            self.keystore.DeleteCertificate(p['CertificateID'])

    def uploadCert(self, cert_b64_der : str, Alias:str = None):
        arg = {"Certificate" : cert_b64_der}
        if Alias:
            arg['Alias'] = Alias
        return self.keystore.UploadCertificate(**arg)
    
    def uploadTest(self):
        print("loading Certificate: ", end = '')
        resp = self.uploadCert(VALID_CERT2, Alias=self.TEST_ALIAS)
        certId = resp['CertificateID']
        if certId == INVALID_ID:
            raise ValueError("failed uploading Certificate")
        obj = self.keystore.GetCertificate(certId)
        if(not obj):
            raise ValueError("uploaded Certificate not found")
        content = base64.b64encode(obj['CertificateContent']).decode('utf-8')
        if(content != VALID_CERT2):
            raise ValueError("Cerificate content is broken")
        id2 = self.uploadCert(VALID_CERT2)
        if(certId == id2): raise ValueError("non-unique ID")
        print("OK")

        # check deleted key
        print("deleteTest: ", end='')
        self.keystore.DeleteCertificate(certId)
        obj = None
        objs = []
        objs = self.keystore.GetAllCertificates()
        obj = CertTest.find(certId, objs)
        if(obj):
            raise ValueError("Certificate still exists")
        print("OK")
        
        print("invalid cert: ", end='')
        certId = None
        try:
            certId = self.uploadCert("INVALIDwefwefwef")
        except Fault as e:
            #normal
            pass
        if(certId and certId != INVALID_ID):
            raise ValueError("INVALID cert uploaded")
        self.clean()
        print("OK")
        print("uploadCertTest passed!")


    def limitTest(self):
        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        limit = caps['KeystoreCapabilities']['MaximumNumberOfCertificates']
        print(f'Certificates limit {limit}: ', end='')
        self.clean()
        
        for i in range(0, limit):
            self.uploadCert(VALID_CERT2, Alias=f'test#{i}')
        # overflow
        obj = None
        try:
            obj = self.uploadCert(VALID_CERT2, Alias=f'test#{limit}')
        except Fault:
            pass
        if(obj and obj['CertificateID'] != INVALID_ID):
            raise ValueError("no upload limit")
        self.clean()
        print('OK')
        print('CertificateLimitTest passed!')

    def cleanKeys(self):
        objs = self.keystore.GetAllKeys()
        for p in objs:
            self.keystore.DeleteKey(p['KeyID'])

    def certKeysTest(self):
        self.clean()
        self.cleanKeys()
        print("cert without keys: ", end='')
        keyId = self.uploadCert(VALID_CERT2)['KeyID']
        if not keyId or keyId == INVALID_ID:
            raise ValueError("invalid keyID")
        
        data = self.keystore.GetPrivateKeyStatus(keyId)
        # print(data)
        if(data == True):
            raise ValueError('key from cert must be public')

        keys = self.keystore.GetAllKeys()
        key = None
        for k in keys:
            if k['KeyID'] == keyId:
                key = k
                break
        if not key:
            raise ValueError('Key wasn`t created')
        if key['hasPrivateKey']:
            raise ValueError('Key must be public')
        print('OK')
        self.clean()
        self.cleanKeys()

        print("cert + key: ", end='')
        keyArg = {"KeyPair" : VALID_KEY2}
        kId = self.keystore.UploadKeyPairInPKCS8(**keyArg)
        kId_2 = self.uploadCert(VALID_CERT2)['KeyID']
        if(kId != kId_2):
            raise ValueError('not linked with private key')
        print('OK')


    def test(self):
        print('********Certificate**********')
        self.clean()
        objs = self.keystore.GetAllCertificates()
        # print(pwds)
        if len(objs):
            raise ValueError("Cant delete Certificates`")

        self.uploadTest()        
        self.limitTest()
        self.certKeysTest()
        self.clean()
        print('delete unexisted cert: ', end = '')
        try:
            self.keystore.DeleteCertificate('ID_0')  
        except Fault as e:
            # normal
            pass
        print('OK')
        print(f'CertTest passed!')