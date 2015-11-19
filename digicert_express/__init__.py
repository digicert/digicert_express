import getpass
import config
import sys
from request import Request
import loggers

def main():
	logger = loggers.get_logger(__name__)
	# check if the certificate was supplied on the command line
	try:
		if not config.API_KEY:
			config.API_KEY = request_login()
	except Exception as ex:
		print ex.message

def request_login():
	logger = loggers.get_logger(__name__)
	# do you have a DigiCert api key? <y>
	logger.info("Please login to continue.")
	username = raw_input("DigiCert Username: ")
	password = getpass.getpass("DigiCert Password: ")

	r = Request().post('/user/tempkey', {'username': username, 'current_password': password})
	if r.has_error:
		if raw_input('Authentication failed! Would you like to try again? [y/n] ') != 'n':
			return request_login()
		else:
			sys.exit("Authentication failed. Unable to continue.")
	return r.data["api_key"]
