from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
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

    def uploadKeypair(self, key_b64_der: str, pwd: str = None, pw_id: str = None, Alias: str = None):
        import base64
        arg = {"KeyPair": base64.b64decode(key_b64_der)}
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
        id = None
        try:            
            id = self.uploadKeypair(VALID_KEY, VALID_PASS, Alias=f'test#{limit}')
        except Fault as e:
            pass
        if(id and id != INVALID_ID):
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