from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
from requests.auth import HTTPDigestAuth
from zeep.exceptions import Fault, TransportError, XMLParseError

from zeep.cache import SqliteCache
cache = SqliteCache(path='./sqlite.db', timeout=60)

SEC_WSDL = 'http://www.onvif.org/ver10/advancedsecurity/wsdl/advancedsecurity.wsdl'
SEC_BINDING = '{http://www.onvif.org/ver10/advancedsecurity/wsdl}AdvancedSecurityServiceBinding'
KEYSTORE_BINDING = '{http://www.onvif.org/ver10/advancedsecurity/wsdl}KeystoreBinding'


INVALID_ID = "INVALID"

class OnvifClient:
    def __init__(self, wsdl : str, user : str, pwd:str):
        self.session = Session()
        self.session.auth = HTTPDigestAuth(user, pwd)
        self.transport = Transport(session=self.session, cache=cache)
        self.client = Client(wsdl=wsdl, transport=self.transport)

    def createService(self, binding, endpoint):
        return self.client.create_service(binding, endpoint)