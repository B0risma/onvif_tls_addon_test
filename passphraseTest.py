from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *

class PassPhraseTest:
    TEST_ALIAS = "TSET"
    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)

    def findPass(id : str, pwds : list, Alias:str = None):
        pwd = None
        for p in pwds:
            if p['PassphraseID'] == id:
                pwd = p
                break
        if Alias and pwd and pwd['Alias'] != Alias:
            print(f'Unexpected Alias: {pwd['Alias']} must be {Alias}')
        return pwd

    def cleanPasses(self):
        pwds = self.keystore.GetAllPassphrases()
        # print(f'current passes: {pwds}')
        for p in pwds:
            self.keystore.DeletePassphrase(p['PassphraseID'])

    def uploadPass(self, pwd : str, Alias:str = None):
        arg = {"Passphrase" : pwd}
        if Alias:
            arg['PassphraseAlias'] = Alias
        return self.keystore.UploadPassphrase(**arg)
    
    def uploadPassTest(self):
        id = self.uploadPass('Test', PassPhraseTest.TEST_ALIAS)
        pwds = self.keystore.GetAllPassphrases()
        pwd = PassPhraseTest.findPass(id, pwds)
        if(not pwd):
            raise ValueError("uploaded pass not found")
        id2 = self.uploadPass("Test2")
        if(id == id2): raise ValueError("non-unique ID")
    
    def passLimitTest(self):
        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        pass_limit = caps['KeystoreCapabilities']['MaximumNumberOfPassphrases']
        print(f'passphrase limit {pass_limit}')
        self.cleanPasses()
        
        for i in range(0, pass_limit):
            self.uploadPass(str(i), f'test#{i}')
        # overflow
        id = self.uploadPass(str(i), f'test#{pass_limit}')
        if(id != INVALID_ID):
            raise ValueError("no upload limit")
        self.cleanPasses()
        print('passLimitTest passed!')
            
            
    def test(self):
        print('********PASSPHRASES*******')
        self.cleanPasses()
        pwds = self.keystore.GetAllPassphrases()
        # print(pwds)
        if len(pwds):
            raise ValueError("Cant delete passphrases`")

        self.uploadPassTest()        
        self.passLimitTest()
        self.cleanPasses()
        try:
            self.keystore.DeletePassphrase('ID_0')  
        except Fault as e:
            # normal
            pass
        print(f'PassPhraseTest passed!')