from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *

VALID_KEY = '''MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIqv7lr+SBkhwCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAGSYLM588mV2fgdn8PdsFkBIIE0DCj06trzCghBoPzCUo1C2WmL+L21Whv+Kt1nmUByvHPeUwfXnMoF14eQzSQ5RTcuNXCvkK2m5X0n2+ld1vWrhyLB5ld1+KUUcQDR99NmtE7PaazQ1fVsrvXn4vBpIZ5FJhh6MVuv5sjyucKKifQ2cLsFwbd23IvDe8WxtX9f/v39BqMKMNEAr7+epdMIzBOYtSH2WS3opNTgyDK/mtXYOFlxYPmWOhE2JQdjR6sgNFE9sGDFb+tu/PWQm2GZzA3a1FN+PvVIq5gb8U/4sOZojvAdD/AZTlDgIisoDVrVLEafFbQ1sGgnbEVXuJZFPQ61sbzIv7kNK+xtW+YK93eHKqSxmzu7HciU0YX6UAYIuQe1T3CQBzgV92psH22dFhecfVKhiBTVtnAelbzUTXkwpGfjMkQrZS0f3wgOMZpZchLYRZmYq2wllKZBDEwytiJcrQj1I825GV+Xfmj7e8OsTs9Zm8KtSSc4nLT8Qz5tsbw2cGnuNNYd1Bk+6uEN7uLmtIgGoMK42nyGCGYF3qaC3hdg4fwjz/pS1LiRmHgEpIwi44yPdtTrZY8hG+xaxTELMJA4946/Yjdk33UST2hOodsaSzbjjJe703X2XdR4vXLUIG6wOqacDwZBQkmww90tBic9y953O8MIgKv15ss5tUy8FsX131psGzAkfaItzEqQPoK5OHXNz2tDAQI4PZaAbPBYAQFY1Crv8W4+goR5d+MtHbpjqDr0+uTVJphn1GU5TL9wO5YKCmUO1pLDOSL7vy/aPRtKdIeO6plFE5N9YYMx91wGmfixpY9ydrzPx63C6Hi9YvRR1AkVpiB1HN7B+6/yGWcmZEijTpaQprySi/yBtsY8lFkeVWrENBwvT7ei8tF7zwz2zDkTlNKxxdJVOGRZ9AlCkfmulQgkM6jcfCEfMG4sdWiz38RI/i8/Ee8orrFq7UXbSInTfRb2xcrY+aOi8CdJrCnqwWNg5m9RCC2dDW/bCwM2YumEfCz6ld6ffLpZAcJVqxfLRdWF4IE7oB24IP2RvGpUloAX3wox9MGFrMZmjCHbLTQRz9pESELzc2nRtyTk3rFLuP7g30WCsUzrNNhp/DtNI3oA1EpcfUKRr4F5xBIE+80tyMkLJ/n6dtobG3gux5Wti0jQwRkqawz9cisRungtxDgQyVEOsKiSJjPE5F19HrdVmgb/iu1wKySNYuIkSGrlCjB0DKdlAJ+5R+ayZw69OQB58sryObt9rFzvGWaXpsZxVTrMuuywDqeQ6aQS81+Epu/jLYa6s8usJXndbNBmyuh0YzC2SiFKbaPqgKfhkl65q+uZKaAMfKzca+TGIAhDm4YKpAyNN4/dVkn0KtHlblaBwAYLV8C5bHBCFVirJib/MhY6NkJS/vi2bzu6L7kb9AypIDaz5WRTYbTA08ealVvyu5cpd8OgkbYhdbIwzGhFyooOxrAdu2tl65qXJTpnkwqqBNtTmxbMEMr4eqH4LC+fkts0aPjFDyi2zHsJ1bMnJWi7Fpy9rOGyYsDTnj2H8pyrhuCImvkMZMe+otWR8tqGDuhCMmlAFg9N+u/aND+yevDZGv8Idgjso0WUBygbK6QJRGlWb3PX51AewaQEByj4t8n8wfv8/3OWO3KYGSIbz877adN'''
VALID_PASS = '1234'
PUBLIC_KEY = '''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3mwDqpmecO+OglzjgI8GIFPBjjpM6DsmWCr4A/8gRhg6yo+grGGFELiXhES8ph+q9QHTG1Y+pzg3/aHVNrEPrRgrPMn5o5UNxzQgoiZbuNIGh6oYuHPDq1cMJbPCzdf3MhoWOdiMCrf3YAIJOltD88GNayuzZXqDQoZ9MmJUlLZtPeAzIDZZNzQONlq8qVBplTweWAB6jLuxJP6nB3pvnLzyZXauUUDOQUMpxShPvNohmrTRJSEimnl/LfjO0bsxYOE/dDSxoSF2ikAR1AgQpl6Qo8anXF4wERWExaf9oiUsg6mDcaOlRgdG7zsPfgoemJtQXVrqWD+F3jxEQtr+ZQIDAQAB'''
VALID_NOCRYPT_KEY = '''MIIEpQIBAAKCAQEA4t/ujOdEa5dyCGNKa+0sL1/Fetdlc83Agzgs/TQE4VDKiWQ4xxqEgiarXfp5jhPw5+rzr8grIUkW7qCZYoQcNjt+feMc6vfYpHsq/l/stTfHvSS0N2ARWOtzUZvDgjLF+lJYCAJHShsZGsT1Ueskcwi712ZxWkVoDelkXPemdcQbRHbLsHrVvkkc4c5kc512gkBlVktdezutXwgrg3F8aYBLrhgKwG1GWx7DDvtUUoIJWgjqlrFNjmCkcnYKnqT6/bFDGGkQ5XpL8EcsbLLi+DDbLDTF0lys/G6flYVImCBJZWV5Mc+wPXh83P1wJrBAbXsUvc0/OVn8FJwNHtfQkwIDAQABAoIBAQDOh6QVyQJUH43DbP/2t/WdOsX/Sc4lWYyC58Ssy4oVwwJdiErXlaBDCwi9iKLXX/fSZ+RmhQYeSvcBTFnVgQZdqFNCLlnI3M7vDODaqGBHp/vAh4U3U9D27YARLocQI0Bu3D8fK1PSdlCoOdxJMpH/1leJgsx1rPFImMqwhxGV6bTcac1USIjoj5UtirZPr/RXxe8mqKcShQzyMrHaaTowqVAMJ22a2qkaD1srclQcs7jHk3HRhzgqkR5TSCF8rUrwAzgFkH2+ZrwNsOjgPS72FMZVJIefDb3grp77OUnTPG+Hx2yPYu8HDxQwRhO1EFJ6DgK7nnubHwHrb+1EYYiBAoGBAPw/NE2b9IRTyfi/wKB5yRKWdF+TG3W6320czSKIlGXLC8Nw3QqgIK9MRAUNdhT1Et0JNB5X54QDJtlOLVKssjn6rbolnWk5cVps7GcO4+/0iE8UEw29CNySKBhyFnmbaE2Ir3YmT/gGvBQAswX/LkzqIV1jEbh06/bhbFyUW1+DAoGBAOZAFhT5+zMDlGHz4h5IPe5iN+KgFnX+EGxN+Ob5M+I+ZA1A2rQLvFPS5h3avaIHA7zbME9W1JfhhT4JDTDTwxvJQ91+nFZEq/S0KibV4N8xb4tHglB7zq/LE/J9qZcq9zz7LnMhZvnbd2EoHHeHWdLs/gpRX3rHrgDC24yMAG2xAoGBAO4p5wJX+7htPEeHFSLvme/Y6qvKw6SW+pmVFgJDHoo1+jdf+vQrWHDq+1Yh7ZnAAz17kSANM2SrbSTD8Xsb33Nqwlj9ZvCQ8fvE2Dg+EOzg30p607qm/xTzUrQyFBJhr0t1gOV3Kw4tnartNhq1Y0vvy+zWu0aD7r88/Ak1ckhtAoGAWYomjDXCmE4WEBmVn40ceG29qeXzliMdI+EWoEvc/2if4/+KjWXa8QYc8xMzl6T+sRzUJqZvuji7ZiqC9LAFOfME70fjaDEAZgMCOWQHNQS2igVfCgl7kSV6Nlzj7KOKzi4oHCGrOBM+04uTtm/uYHZFPKH0bXzlj+o3EusG56ECgYEA7KVMIkh+f17CcXRqk+QW5H/FJGVIuDojQClgdLh+d3lL93150jIynnptFfQQ5lTGgPVCOzi7YJicHs4knyLq25XpC6w2NZJaVxrjCsU1GNf5hJ3QSUV2N4QSEN5kg+qIJ7UQCyjk86YaQCWdz9KJ8ZKG3juiPvOdnFU084CXCwQ='''



class KeyTest:
    TEST_ALIAS = "TSET"
    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)

    def find(id : str, keys : list, Alias:str = None):
        key = None
        for p in keys:
            if p['KeyID'] == id:
                key = p
                break
        if Alias and key and key['Alias'] != Alias:
            print(f'Unexpected Alias: {key['Alias']} must be {Alias}')
        return key
    
    def clean(self):
        objs = self.keystore.GetAllKeys()
        # print(f'current passes: {pwds}')
        for p in objs:
            self.keystore.DeleteKey(p['KeyID'])

    def uploadKeypair(self, key_b64_der : str, pwd : str = None, pw_id:str = None, Alias:str = None):
        arg = {"KeyPair" : key_b64_der}
        if pwd:
            arg["EncryptionPassphrase"] = pwd
        elif pw_id:
            arg["EncryptionPassphraseID"] = pw_id
        if Alias:
            arg['Alias'] = Alias
        return self.keystore.UploadKeyPairInPKCS8(**arg)
    
    def uploadTest(self):
        print("loading key: ", end = '')
        id = self.uploadKeypair(VALID_KEY,pwd=VALID_PASS, Alias="private") # uploading private key 
        if id == INVALID_ID:
            raise ValueError("failed uploading key")
        objs = self.keystore.GetAllKeys()
        obj = KeyTest.find(id, objs)
        if(not obj):
            raise ValueError("uploaded key not found")
        if(not obj['hasPrivateKey']):
            raise ValueError("cant resolve private keys")
        print("OK")

        print('getting key status: ', end ='')
        data = self.keystore.GetKeyStatus(id)
        if(data != 'ok'): # from KeyStatus enum (wsdl)
            raise ValueError('key not OK')
        data = self.keystore.GetPrivateKeyStatus(id)
        if(data != True): 
            raise ValueError('key must be private')
        print("OK")
        
        self.keystore.DeleteKey(id)
        id = None
        # no pwd - must be error
        print("encrypted key + no pass ", end = '')
        try:
            id = self.uploadKeypair(VALID_KEY, Alias="private") # uploading private key 
        except Exception as e:
            # print(f'{type(e).__name__}: {e}')
            id = None
        if id and id != INVALID_ID:
            raise ValueError("UploadKeypair must be invalid or error")
        print("OK")

        print("key + passID: ", end = '')
        p_id = self.keystore.UploadPassphrase(**{'Passphrase': VALID_PASS})
        if p_id == INVALID_ID:
            raise ValueError("cant upload passphrase")
        id = self.uploadKeypair(VALID_KEY, pw_id=p_id)
        if id == INVALID_ID:
            raise ValueError("cant upload key")
        objs = self.keystore.GetAllKeys()
        obj = KeyTest.find(id, objs)
        if(not obj):
            raise ValueError('Key wasn`t uploaded')
        print("OK")
        id2 = self.uploadKeypair(VALID_KEY, VALID_PASS)
        if(id == id2): raise ValueError("non-unique ID")

        # invalid key
        print("invalid key: ", end = '')
        id = None
        try:
            id = self.uploadKeypair("test", Alias="invalid")
        except Fault as e:
            #normal
            pass
        # alternative hadling
        if(id and id != INVALID_ID):
            raise ValueError("INVALID key uploaded!")
        print('OK')

        print("pub key: ",end='')
        id = None
        try:
            id = self.uploadKeypair(PUBLIC_KEY, Alias="Pulbic")
        except Fault as e:
            #normal
            pass
        # alternative hadling
        if(id and id != INVALID_ID):
            raise ValueError("public key uploading failed")
        print("OK")

        print("nocrypt key: ",end='')
        id = None
        id = self.uploadKeypair(VALID_NOCRYPT_KEY, Alias="NOCRYPT")
        # alternative hadling
        if(id == INVALID_ID):
            raise ValueError("nocrypt key uploading failed")
        print("OK")
        print("uploadKeyTest passed!")


    def limitTest(self):
        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        limit = caps['KeystoreCapabilities']['MaximumNumberOfKeys']
        print(f'keys limit {limit}')
        self.clean()
        
        for i in range(0, limit):
            self.uploadKeypair(VALID_KEY, VALID_PASS, Alias=f'test#{i}')
        # overflow
        id = self.uploadKeypair(VALID_KEY, VALID_PASS, Alias=f'test#{limit}')
        if(id != INVALID_ID):
            raise ValueError("no upload limit")
        self.clean()
        print('KeylimitTest passed!')

    def test(self):
        print('********KEYS**********')
        self.clean()
        objs = self.keystore.GetAllKeys()
        # print(pwds)
        if len(objs):
            raise ValueError("Cant delete keys`")

        self.uploadTest()        
        self.limitTest()
        self.clean()
        try:
            self.keystore.DeleteKey('ID_0')  
        except Fault as e:
            # normal
            pass
        print(f'KeyTest passed!')