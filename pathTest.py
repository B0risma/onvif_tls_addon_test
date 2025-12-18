from zeep.exceptions import Fault, TransportError, XMLParseError

from onvifClient import *
from certTest import *
from keyTest import *

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
    
    def setCertPathArgs(pathId:str, idList:list):
        arg = {
            'CertificationPathID':pathId,
            'CertificationPath' : {
                'CertificateID' : idList
            }
            }
        return arg
    
    def uploadTest(self):
        self.clean()

        print('loading one size path: ', end ='')
        path_id = self.createCertPath([CERT_1])
        if path_id == INVALID_ID:
            raise ValueError("cant create valid path")
        self.clean()
        print("OK")

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

        print('setting new valid order: ', end = '')
        oldObj = self.keystore.GetCertificationPath(path_id)
        certIds = oldObj['CertificateID']
        # print(certIds)
        certIds = certIds[:-1]
        # print(certIds)
        args = PathTest.setCertPathArgs(path_id, certIds)
        self.keystore.SetCertificationPath(**args)
        newObj = self.keystore.GetCertificationPath(path_id)
        if(newObj == oldObj):
            raise ValueError('can`t change path')
        self.clean()
        print("OK")

    # def setTest(self):
    #     print("loading path (size 3): ", end = '')
    #     path_id = self.createCertPath([CERT_3, CERT_2, CERT_1])
    #     if path_id == INVALID_ID:
    #         raise ValueError("cant create valid path")
    #     self.keystore.GetCertificationPath(path_id)
    #     self.clean()
    #     print("OK")

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