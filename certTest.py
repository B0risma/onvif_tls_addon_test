from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
import base64

VALID_CERT = '''MIICwTCCAakCFBOiKOKJ1sHs/CioQMsgUqiLR6yQMA0GCSqGSIb3DQEBCwUAMB4xCzAJBgNVBAYTAlJVMQ8wDQYDVQQDDAZpbnRlcjIwHhcNMjUxMjA1MDY0ODU5WhcNMjYxMjA1MDY0ODU5WjAcMQswCQYDVQQGEwJSVTENMAsGA1UEAwwEdXNlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOLf7oznRGuXcghjSmvtLC9fxXrXZXPNwIM4LP00BOFQyolkOMcahIImq136eY4T8Ofq86/IKyFJFu6gmWKEHDY7fn3jHOr32KR7Kv5f7LU3x70ktDdgEVjrc1Gbw4IyxfpSWAgCR0obGRrE9VHrJHMIu9dmcVpFaA3pZFz3pnXEG0R2y7B61b5JHOHOZHOddoJAZVZLXXs7rV8IK4NxfGmAS64YCsBtRlseww77VFKCCVoI6paxTY5gpHJ2Cp6k+v2xQxhpEOV6S/BHLGyy4vgw2yw0xdJcrPxun5WFSJggSWVleTHPsD14fNz9cCawQG17FL3NPzlZ/BScDR7X0JMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAtYXr2N5jn4Ukmx4QbbEHOm0TxJE6dSyL2a9bIkqcHGCBq8DC5QjOsocA/tOW7ulU8+hvfgw9sV/FzyUtVa/CLnCNIswTT7SH7KtPlJCj6hmS+ESdMOMzO9ZJfrLXCQXk+BM1NHf5aHKT3t388w+gGr7C7+HR7VBeU0EgHb1kENdTNjemxPUY9Msud4ObTh5PjJHPLLuibt1+Ej3tzzBPsUz6IWzLaa28oiZfMPN3Y5zFDf7OKr+tDYOE6x8Izqw4JSz7FA9rNJMobFEd+H31BvgbW09jmXog+Jz0HrVNL4UABZeMMxHC60XDpF8JexalFS+ojME6Qc5IXwSjK+YEbA=='''
VALID_KEY = '''MIIEpQIBAAKCAQEA4t/ujOdEa5dyCGNKa+0sL1/Fetdlc83Agzgs/TQE4VDKiWQ4xxqEgiarXfp5jhPw5+rzr8grIUkW7qCZYoQcNjt+feMc6vfYpHsq/l/stTfHvSS0N2ARWOtzUZvDgjLF+lJYCAJHShsZGsT1Ueskcwi712ZxWkVoDelkXPemdcQbRHbLsHrVvkkc4c5kc512gkBlVktdezutXwgrg3F8aYBLrhgKwG1GWx7DDvtUUoIJWgjqlrFNjmCkcnYKnqT6/bFDGGkQ5XpL8EcsbLLi+DDbLDTF0lys/G6flYVImCBJZWV5Mc+wPXh83P1wJrBAbXsUvc0/OVn8FJwNHtfQkwIDAQABAoIBAQDOh6QVyQJUH43DbP/2t/WdOsX/Sc4lWYyC58Ssy4oVwwJdiErXlaBDCwi9iKLXX/fSZ+RmhQYeSvcBTFnVgQZdqFNCLlnI3M7vDODaqGBHp/vAh4U3U9D27YARLocQI0Bu3D8fK1PSdlCoOdxJMpH/1leJgsx1rPFImMqwhxGV6bTcac1USIjoj5UtirZPr/RXxe8mqKcShQzyMrHaaTowqVAMJ22a2qkaD1srclQcs7jHk3HRhzgqkR5TSCF8rUrwAzgFkH2+ZrwNsOjgPS72FMZVJIefDb3grp77OUnTPG+Hx2yPYu8HDxQwRhO1EFJ6DgK7nnubHwHrb+1EYYiBAoGBAPw/NE2b9IRTyfi/wKB5yRKWdF+TG3W6320czSKIlGXLC8Nw3QqgIK9MRAUNdhT1Et0JNB5X54QDJtlOLVKssjn6rbolnWk5cVps7GcO4+/0iE8UEw29CNySKBhyFnmbaE2Ir3YmT/gGvBQAswX/LkzqIV1jEbh06/bhbFyUW1+DAoGBAOZAFhT5+zMDlGHz4h5IPe5iN+KgFnX+EGxN+Ob5M+I+ZA1A2rQLvFPS5h3avaIHA7zbME9W1JfhhT4JDTDTwxvJQ91+nFZEq/S0KibV4N8xb4tHglB7zq/LE/J9qZcq9zz7LnMhZvnbd2EoHHeHWdLs/gpRX3rHrgDC24yMAG2xAoGBAO4p5wJX+7htPEeHFSLvme/Y6qvKw6SW+pmVFgJDHoo1+jdf+vQrWHDq+1Yh7ZnAAz17kSANM2SrbSTD8Xsb33Nqwlj9ZvCQ8fvE2Dg+EOzg30p607qm/xTzUrQyFBJhr0t1gOV3Kw4tnartNhq1Y0vvy+zWu0aD7r88/Ak1ckhtAoGAWYomjDXCmE4WEBmVn40ceG29qeXzliMdI+EWoEvc/2if4/+KjWXa8QYc8xMzl6T+sRzUJqZvuji7ZiqC9LAFOfME70fjaDEAZgMCOWQHNQS2igVfCgl7kSV6Nlzj7KOKzi4oHCGrOBM+04uTtm/uYHZFPKH0bXzlj+o3EusG56ECgYEA7KVMIkh+f17CcXRqk+QW5H/FJGVIuDojQClgdLh+d3lL93150jIynnptFfQQ5lTGgPVCOzi7YJicHs4knyLq25XpC6w2NZJaVxrjCsU1GNf5hJ3QSUV2N4QSEN5kg+qIJ7UQCyjk86YaQCWdz9KJ8ZKG3juiPvOdnFU084CXCwQ='''


class CertTest:
    TEST_ALIAS = "TSET"
    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)

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
        resp = self.uploadCert(VALID_CERT, Alias=self.TEST_ALIAS)
        certId= resp['CertificateID']
        if certId == INVALID_ID:
            raise ValueError("failed uploading Certificate")
        obj = self.keystore.GetCertificate(certId)
        if(not obj):
            raise ValueError("uploaded Certificate not found")
        content = base64.b64encode(obj['CertificateContent']).decode('utf-8')
        if(content != VALID_CERT):
            raise ValueError("Cerificate content is broken")
        id2 = self.uploadCert(VALID_CERT)
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
            self.uploadCert(VALID_CERT, Alias=f'test#{i}')
        # overflow
        obj = self.uploadCert(VALID_CERT, Alias=f'test#{limit}')
        if(obj['CertificateID'] != INVALID_ID):
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
        keyId = self.uploadCert(VALID_CERT)['KeyID']
        if not keyId or keyId == INVALID_ID:
            raise ValueError("invalid keyID")
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
        keyArg = {"KeyPair" : VALID_KEY}
        kId = self.keystore.UploadKeyPairInPKCS8(**keyArg)
        kId_2 = self.uploadCert(VALID_CERT)['KeyID']
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