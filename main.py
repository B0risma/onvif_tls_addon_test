# full ONVIF TLS Add-on test

from onvifClient import *
from passphraseTest import *
from keyTest import *
from certTest import *
from pathTest import *
from policyTest import *
from dotXTest import *

# Camera credentials
CAMERA_IP = "192.168.7.155"
USERNAME = "admin"
PASSWORD = "Admin123"

def test():
    for i in range(0,1):
        print(f'run #{i+1}')
        PassPhraseTest(CAMERA_IP, USERNAME, PASSWORD).test()
        KeyTest(CAMERA_IP, USERNAME, PASSWORD).test()
        CertTest(CAMERA_IP, USERNAME, PASSWORD).test()
        PathTest(CAMERA_IP, USERNAME, PASSWORD).test()
        PolicyTest(CAMERA_IP, USERNAME, PASSWORD).test()
        DotXTest(CAMERA_IP, USERNAME, PASSWORD).test()
    print("ALL OK!")
# try:
test()
# except Exception as e:
#     print(f"Error: {type(e).__name__}: {e}")