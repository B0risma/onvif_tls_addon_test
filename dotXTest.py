from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from certTest import *
from passphraseTest import *
from policyTest import *
from pathTest import *
from keyTest import *

class DotXTest:

    def __init__(self, ip, user, pwd):
        self.client = OnvifClient(SEC_WSDL, user, pwd)
        self.endp =  f'http://{ip}/onvif/security_service'
        self.keystore = self.client.createService(KEYSTORE_BINDING, self.endp)
        self.dotxSrv = self.client.createService(DOTX_BINDING, self.endp)  
        self.policyLoader = PolicyTest(ip, user, pwd)
        self.pathLoader = PathTest(ip, user, pwd)
        self.passLoader = PassPhraseTest(ip, user, pwd)
        self.certLoader = CertTest(ip, user, pwd)
        self.keyloader = KeyTest(ip, user, pwd)

        self.ip = ip
        self.user = user
        self.pwd = pwd

    def find(id : str, objs : list):
        obj = None
        for p in objs:
            if p['Dot1XID'] == id:
                obj = p
                break
        return obj
    
    def clean(self):
        self.policyLoader.clean()
        self.pathLoader.clean()
        self.passLoader.cleanPasses()
        self.certLoader.clean()
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        # print(objs)
        for obj in objs:
            id = obj['Dot1XID']
            self.dotxSrv.DeleteDot1XConfiguration(id)

    def getUserPassArg(user:str, pwdId:str) -> dict:
        return {
                'Identity' : user,
                'PassphraseID' : pwdId
            }
    
    def getFullArg(outer: dict, alias:str):
        return {
            'Dot1XConfiguration':{
               'Alias' : alias,
                'Outer' :  outer
            }
        }
    
    def addMD5(self, user:str, pwd:str):
        pwdId = self.passLoader.uploadPass(pwd)
        arg = DotXTest.getUserPassArg(user, pwdId)
        arg['Method'] = 'MD5-Challenge'
        args = DotXTest.getFullArg(arg,'md5')
        return self.dotxSrv.AddDot1XConfiguration(**args)

    def addMSCHAP(self, user:str, pwd:str):
        pwdId = self.passLoader.uploadPass(pwd)
        arg = DotXTest.getUserPassArg(user, pwdId)
        arg['Method'] = 'EAP-MSCHAP-V2'
        args = DotXTest.getFullArg(arg, 'mschap')
        return self.dotxSrv.AddDot1XConfiguration(**args)
    
    def addPEAP(self, user:str, pwd:str):
        pwdId = self.passLoader.uploadPass(pwd)
        inner = DotXTest.getUserPassArg(user, pwdId)
        inner['Method'] = 'EAP-MSCHAP-V2'
        outer = {
            'Method' : "EAP-PEAP",
            'Inner' : inner
        }
        args = DotXTest.getFullArg(outer, 'peap')
        return self.dotxSrv.AddDot1XConfiguration(**args)
    
    def addTTLS(self, user:str, pwd:str, CAcrt:str):
        pwdId = self.passLoader.uploadPass(pwd)
        crtId = self.certLoader.uploadCert(CAcrt)['CertificateID']
        if(crtId == INVALID_ID):
            raise ValueError('Cant create cert')
        polId = self.policyLoader.loadPolicy([crtId])
        if(polId == INVALID_ID):
            raise ValueError('Cant create policy')
        inner = DotXTest.getUserPassArg(user, pwdId)
        inner['Method'] = 'MD5-Challenge'
        outer = {
            'Method' : "EAP-TTLS",
            'CertPathValidationPolicyID' : polId,
            'Inner' : inner
        }
        args = DotXTest.getFullArg(outer, 'ttls')
        return self.dotxSrv.AddDot1XConfiguration(**args)
    
    def addTLS(self, CAcrt:str, usrCrt:str, usrKey:str, keyPass:str = None):
        #CA cert for policy
        CA_id = self.certLoader.uploadCert(CAcrt)['CertificateID']
        if(CA_id == INVALID_ID):
            raise ValueError('Cant create cert')
        pols = self.keystore.GetAllCertPathValidationPolicies()
        if(len(pols)):
            raise ValueError("policies dont clean")
        polId = self.policyLoader.loadPolicy([CA_id])
        if(polId == INVALID_ID):
            raise ValueError('Cant create policy')
        
        # user cert for auth as certPath
        usrKeyId = self.keyloader.uploadKeypair(usrKey, keyPass)
        pathId = self.pathLoader.createCertPath([usrCrt])
        if(pathId == INVALID_ID):
            raise ValueError('Cant create path')
        outer = {
            'Method' : "EAP-TLS",
            'CertPathValidationPolicyID' : polId,
            'Identity' : 'Test',
            'CertificationPathID' : pathId
        }
        args = DotXTest.getFullArg(outer, 'TLS')
        return self.dotxSrv.AddDot1XConfiguration(**args)

    
    def uploadTest(self):
        self.clean()
        print('adding MD5: ', end = '')
        objId = self.addMD5('test', 'pass')
        # set breakpoint here to check data on cam
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        obj = DotXTest.find(objId, objs)
        # print(f"{obj}")
        if(not obj):
            raise ValueError("DotX wasn`t added")
        obj2 = self.dotxSrv.GetDot1XConfiguration(objId)
        if(obj != obj2):
            raise ValueError("invalid dotX cfg")
        if(obj2['Outer']['Method'] != 'MD5-Challenge'):
            print(obj2)
            raise ValueError("invalid dotX cfg")
        self.clean()
        print('OK')

        print('adding MSCHAP: ', end = '')
        objId = self.addMSCHAP('test', 'pass')
        # set breakpoint here to check data on cam
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        obj = DotXTest.find(objId, objs)
        # print(f"{obj}")
        if(not obj):
            raise ValueError("DotX wasn`t added")
        obj2 = self.dotxSrv.GetDot1XConfiguration(objId)
        if(obj != obj2):
            raise ValueError("invalid dotX cfg")
        if(obj2['Outer']['Method'] != 'EAP-MSCHAP-V2'):
            print(obj2)
            raise ValueError("invalid dotX cfg")
        self.clean()
        print('OK')        

        print('adding EAP-PEAP: ', end = '')
        objId = self.addPEAP('test', 'pass')
        # set breakpoint here to check data on cam
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        obj = DotXTest.find(objId, objs)
        # print(f"{obj}")
        if(not obj):
            raise ValueError("DotX wasn`t added")
        obj2 = self.dotxSrv.GetDot1XConfiguration(objId)
        if(obj != obj2):
            raise ValueError("invalid dotX cfg")
        if(obj2['Outer']['Method'] != 'EAP-PEAP'):
            print(obj2)
            raise ValueError("invalid dotX cfg")
        self.clean()
        print('OK')

        print('adding TTLS: ', end = '')
        objId = self.addTTLS('test', 'pass', CERT_1)
        # set breakpoint here to check data on cam
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        obj = DotXTest.find(objId, objs)
        # print(f"{obj}")
        if(not obj):
            raise ValueError("DotX wasn`t added")
        obj2 = self.dotxSrv.GetDot1XConfiguration(objId)
        if(obj != obj2):
            raise ValueError("invalid dotX cfg")
        if(obj2['Outer']['Method'] != 'EAP-TTLS'):
            print(obj2)
            raise ValueError("invalid dotX cfg")
        self.clean()
        print('OK')

        print('adding TLS: ', end = '')
        # VALID_CERT2 generated from VALID_KEY2
        objId = self.addTLS(CERT_1, VALID_CERT2, VALID_KEY2)
        # set breakpoint here to check data on cam
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        obj = DotXTest.find(objId, objs)
        # print(f"{obj}")
        if(not obj):
            raise ValueError("DotX wasn`t added")
        obj2 = self.dotxSrv.GetDot1XConfiguration(objId)
        if(obj != obj2):
            raise ValueError("invalid dotX cfg")
        if(obj2['Outer']['Method'] != 'EAP-TLS'):
            print(obj2)
            raise ValueError("invalid dotX cfg")
        self.clean()
        print('OK')

        print("UploadTest passed!")

    def bindingTest(self):
        # bind DotX to iface
        devClient = OnvifClient(DEV_WSDL, self.user, self.pwd)
        devSrv = devClient.createService(DEV_BINDING, f'http://{self.ip}/onvif/device_service')
        data = devSrv.GetNetworkInterfaces()
        # print(data)
        iface = data[0]['token']
        if(not iface):
            raise ValueError('no iface')
        
        try:
            self.dotxSrv.DeleteNetworkInterfaceDot1XConfiguration(iface)
        except Fault as e:
            #normal
            pass

        dotxId = self.addMD5('test','test')
        if(dotxId == INVALID_ID):
            raise ValueError("dotX wasnt added")
        args = {
            'token' : iface,
            'Dot1XID' : dotxId
        }
        self.dotxSrv.SetNetworkInterfaceDot1XConfiguration(**args)
        dotXId2 = self.dotxSrv.GetNetworkInterfaceDot1XConfiguration(iface)
        if(dotxId != dotXId2):
            raise ValueError("dotxIds don`t equal")
        
        # clean must be ok
        # add breakpoint here to test that ONVIF binding enbaling DotX (check SokolAPI)
        self.dotxSrv.DeleteNetworkInterfaceDot1XConfiguration(iface)
        # must be ok and empty
        self.dotxSrv.GetNetworkInterfaceDot1XConfiguration(iface)
        self.clean()


    def limitTest(self):
        self.clean()
        caps_srv = self.client.createService(SEC_BINDING, self.endp)
        caps = caps_srv.GetServiceCapabilities()
        limit = caps['Dot1XCapabilities']['MaximumNumberOfDot1XConfigurations']
        print(f'DotX limit {limit}: ', end='')
        for i in range(0, limit):
            self.addMD5('test','test')
        
        status = False
        try:
            # overflow
            status = self.addMD5('test','test')
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
        print('********DOT1_X**********')
        self.clean()
        objs = self.dotxSrv.GetAllDot1XConfigurations()
        # print(objs)
        if len(objs):
            raise ValueError("Cant delete DotX`")
        self.uploadTest() 
        self.bindingTest()
        self.limitTest()
        self.clean()
        print(f'DOTXTest passed!')