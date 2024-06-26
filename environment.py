import json
import sys
import logging
import socket

logging.basicConfig(level=logging.INFO)


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP


class currentMode():
	def __init__(self, mychain, myenv):
		self.test = True
		self.myenv = myenv
		self.ipfs_gateway = 'https://talao.mypinata.cloud/ipfs/'
		try:
			keys = json.load(open('keys.json'))
		except Exception:
			logging.error('keys.json file problem')
			sys.exit()
		self.talao_secp256kr = keys['talao_secp256kr']
		self.talao_P256_private_key = keys['talao_P256_private_key']
		self.talao_Ed25519_private_key = keys['talao_Ed25519_private_key']
		# upload of main private passwords. This file (passwords.json) is not in the  github repo.
		try:
			passwords = json.load(open('passwords.json'))
		except Exception:
			logging.error('passwords.json file problem')
			sys.exit()
		self.password = passwords['password']
		self.admin = passwords['password']
		self.smtp_password = passwords['smtp_password'] # used in smtp.py
		self.pinata_api_key = passwords['pinata_api_key'] # used in Talao_ipfs.py
		self.pinata_secret_api_key = passwords['pinata_secret_api_key'] # used in Talao_ipfs.py
		self.sms_token = passwords['sms_token'] # used in sms.py
		self.github = passwords['github'] # used for test credeible
		self.deeplink_talao = 'https://app.talao.co/'	
		self.deeplink_altme = 'https://app.altme.io/'		
		if self.myenv == 'aws':
			self.flaskserver = "127.0.0.1" # default value to avoid pb with aws
			self.port = 4000 #default value to avoid pb with aws
			self.sys_path = '/home/admin'
			self.server = 'https://talao.co/'
			self.IP = '18.190.21.227' # talao.co
		elif self.myenv == 'local':
			self.sys_path = '/home/thierry'
			self.flaskserver = extract_ip()
			self.IP = extract_ip()
			#self.server = "https://4bfc7921252c.ngrok.app/"
			self.server = 'http://' + self.flaskserver + ':3000/'
			self.port = 3000
		else:
			logging.error('environment variable problem')
			sys.exit()
