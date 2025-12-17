from onvifClient import *
from passphraseTest import *
from keyTest import *
from certTest import *
from pathTest import *
from policyTest import *

# Camera credentials
CAMERA_IP = "192.168.7.155"
USERNAME = "admin"
PASSWORD = "Admin123"

# try:
PassPhraseTest(CAMERA_IP, USERNAME, PASSWORD).test()
KeyTest(CAMERA_IP, USERNAME, PASSWORD).test()
CertTest(CAMERA_IP, USERNAME, PASSWORD).test()
PathTest(CAMERA_IP, USERNAME, PASSWORD).test()
PolicyTest(CAMERA_IP, USERNAME, PASSWORD).test()

# delete unexisted test
print("ALL OK!")
# except Exception as e:
    # print(f"Error: {type(e).__name__}: {e}")