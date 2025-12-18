from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from certTest import *
from keyTest import *

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
    
    def createCertArgs(certIds:list, alias:str = TEST_ALIAS):
        arg =  {
                # 'CertPathValidationPolicyID' : id,
                'Parameters' : {},
                'Alias' : alias,
        }
        if(len(certIds)):
            arg['TrustAnchor'] = []
        for i in certIds:
            arg['TrustAnchor'].append({'CertificateID' : i})
        return arg
    
    def clean(self):
        # print("clean policies")
        self.keyLoader.clean()
        self.certLoader.clean()
        objs = self.keystore.GetAllCertPathValidationPolicies()
        # print(objs)
        for obj in objs:
            id = obj['CertPathValidationPolicyID']
            self.keystore.DeleteCertPathValidationPolicy(id)
        objs = self.keystore.GetAllCertPathValidationPolicies()

        if(len(objs)):
            raise ValueError('PolicyTest.Clean dont work!')
    
    def loadPolicy(self, certIds : list):
        args = PolicyTest.createCertArgs(certIds)
        # print(f'toLoad:{args}')
        return self.keystore.CreateCertPathValidationPolicy(**args)
    
    def unpackTrustList(trustL):
        addedIds = []
        for id in trustL:
            addedIds.append(id['CertificateID'])
        # print(f'TrustL: {addedIds}')
        return addedIds

    def uploadTest(self):
        self.clean()
        print('Loading policy + existed cert', end = '')
        certIds = [self.certLoader.uploadCert(CERT_1)['CertificateID']]
        objId = self.loadPolicy(certIds)
        objs = self.keystore.GetAllCertPathValidationPolicies()
        obj = PolicyTest.find(objId, objs)
        # print(f"{obj}")
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
        # print(obj)
        if(not obj):
            raise ValueError("certPolicy doesn`t exist")
        if certIds != PolicyTest.unpackTrustList(obj['TrustAnchor']):
            raise ValueError("invalid certIds")
        # self.clean() #skip cleaning for next test
        print('OK')
        print('setting 2 certs: ', end='')
        certIds = certIds[:1]
        # args = {'CertPathValidationPolicyID'}
        oldObj = self.keystore.GetCertPathValidationPolicy('default')        
        args = {
            'CertPathValidationPolicyID' : objId,
            'CertPathValidationPolicy' : PolicyTest.createCertArgs(certIds)
        }
        args['CertPathValidationPolicy']['CertPathValidationPolicyID'] = objId # this no error - just stupid arg structure!
        self.keystore.SetCertPathValidationPolicy(**args)
        newObj = self.keystore.GetCertPathValidationPolicy('default')
        if(newObj == oldObj):
            raise ValueError('change policy failed')
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
        self.limitTest()
        self.clean()
        print(f'PolicyTest passed!')