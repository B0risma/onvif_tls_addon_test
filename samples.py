# sample DotX only tests
# HOW to use:
# just run to check 
# - need check data manually or need only one config?
#     set breakpoint after dotxSender.addXXX() and see data on cam

from onvifClient import *
from passphraseTest import *
from keyTest import *
from certTest import *
from pathTest import *
from policyTest import *
from dotXTest import *

from subprocess import check_output
import base64
import logging.config

# request data logging
logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(name)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'zeep.transports': {
            'level': 'DEBUG',
            'propagate': True,
            'handlers': ['console'],
        },
    }
})

# camera login
CAMERA_IP = "192.168.7.155"
USERNAME = "admin"
PASSWORD = "Admin123"

USER = 'test'
PWD = 'Test'

# certs can be expired -> replace with your own (from freeradius)
CA_CERT_F = './certs/ca.pem'
USER_CERT_F = './certs/user.pem'
USER_KEY_F = './certs/user.key'
KEY_PASSWORD = 'whatever' #freeradius default

ca_der = check_output(['openssl', 'x509', '-inform', 'PEM', '-in', CA_CERT_F, '-outform', 'DER'])
ca_crt_b64DER = base64.b64encode(ca_der).decode('utf-8')

user_der = check_output(['openssl', 'x509', '-inform', 'PEM', '-in', USER_CERT_F, '-outform', 'DER'])
user_crt_b64DER = base64.b64encode(user_der).decode('utf-8')

userK_der = check_output(['openssl', 'rsa', '-inform', 'PEM', '-in', USER_KEY_F, '-outform', 'DER', '-passin', 'pass:'+KEY_PASSWORD])
user_key_b64DER = base64.b64encode(userK_der).decode('utf-8')

dotxSender = DotXTest(CAMERA_IP, USERNAME, PASSWORD)
# clean old related data
dotxSender.clean()
# add MD5 config
id = dotxSender.addMD5(USER, PWD)
print(f'MD5 cfg OK')
# clean if needed
dotxSender.clean()

# add MSCHAP config
id = dotxSender.addMSCHAP(USER, PWD)
print(f'MSCHAP cfg OK')
# clean if needed
dotxSender.clean()

# add PEAP-MSCHAP config
id = dotxSender.addPEAP(USER, PWD)
print(f'PEAP cfg OK')
# clean if needed
dotxSender.clean()

# add TTLS/MD5 config
id = dotxSender.addTTLS(USER, PWD, ca_crt_b64DER)
print(f'TTLS cfg OK')
# clean if needed
dotxSender.clean()

# add TTLS/MD5 config
id = dotxSender.addTLS(ca_crt_b64DER, user_crt_b64DER, user_key_b64DER, keyPass=KEY_PASSWORD)
print(f'TLS cfg OK')
# clean if needed
dotxSender.clean()
