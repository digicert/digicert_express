import loggers
import platform
import re
import os
import config
import OpenSSL
from httplib import HTTPSConnection
from platforms import centos_platform, ubuntu_platform

def find_user_config():
    """
    see if there is a custom configuration file in the user's home folder and update the config vars appropriately
    """
    import os
    import json
    home = os.path.expanduser("~")
    if os.path.isfile("{0}/.digicert_express".format(home)):
        cfg = open("{0}/.digicert_express".format(home), "r").read()
        usercfg = json.loads(cfg)
        if 'SERVICES_URL' in usercfg and usercfg['SERVICES_URL']:
            config.SERVICES_URL = usercfg['SERVICES_URL']
        if 'API_KEY' in usercfg and usercfg['API_KEY']:
            config.API_KEY = usercfg['API_KEY']
        if 'FILE_STORE' in usercfg and usercfg['FILE_STORE']:
            config.FILE_STORE = usercfg['FILE_STORE']
        if 'SEARCH_PATHS' in usercfg and usercfg['SEARCH_PATHS']:
            config.SEARCH_PATHS = usercfg['SEARCH_PATHS']
        if 'LOG_FILE' in usercfg and usercfg['LOG_FILE']:
            config.LOG_FILE = usercfg['LOG_FILE']

def normalize_common_name_file(common_name):
    return common_name.replace("*", "any").replace(".", "_")

def determine_platform():
    logger = loggers.get_logger(__name__)
    distro_name = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    logger.debug("Found platform: {0}".format(" : ".join(distro_name)))
    if distro_name[0] == "CentOS":
        return centos_platform.CentosPlatform()
    else:
        return ubuntu_platform.UbuntuPlatform()

def create_regex(text):
    """
    Escape and return the passed string in upper and lower case to match regardless of case.
    Augeas 1.0 supports the standard regex /i but previous versions do not.  Also, not all (but most) unix/linux
    platforms support /i.  So this is the safest method to ensure matches.

    :param text: string to create regex from
    :return: regex
    """

    return "".join(["[" + c.upper() + c.lower() + "]" if c.isalpha() else c for c in re.escape(text)])

# TODO should we add the order_id and sub_id to always make this unique?
def save_certs(certs, dns_name):
    cert_path = '{0}/{1}/{1}.crt'.format(config.FILE_STORE, normalize_common_name_file(dns_name))
    with open(cert_path, 'w') as cert_file:
        cert_file.write(certs['certificate'])
    intermediate_path = '{0}/{1}/DigiCertCA.crt'.format(config.FILE_STORE, normalize_common_name_file(dns_name))
    with open(intermediate_path, 'w') as int_file:
        int_file.write(certs['intermediate'])
    return cert_path

def get_dns_names_from_cert(cert_path):
    logger = loggers.get_logger(__name__)
    if not cert_path or not os.path.isfile(cert_path):
        logger.info("Couldn't find valid certificate file at {0}".format(cert_path))
        return []

    dns_names = []
    sans = ""
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(cert_path, 'r').read())
    for idx in range(cert.get_extension_count()):
        ext = cert.get_extension(idx)
        if ext.get_short_name() == 'subjectAltName':
            sans = str(ext)  # DNS:nocsr.com
            break
    dns_names = [x.split(':')[1] for x in sans.split(',') if x]
    return dns_names

def create_csr(dns_name, order=None):
    """
    Uses this data to create a CSR via OpenSSL
    :param dns_name:
    :param order:
    :return:
    """
    logger = loggers.get_logger(__name__)
    logger.info("Creating CSR file for {0}...".format(dns_name))

    if not os.path.isdir("{0}/{1}".format(config.FILE_STORE, normalize_common_name_file(dns_name))):
        os.makedirs("{0}/{1}".format(config.FILE_STORE, normalize_common_name_file(dns_name)), 0755)

    key_file_name = "{0}/{1}/{1}.key".format(config.FILE_STORE, normalize_common_name_file(dns_name))
    csr_file_name = "{0}/{1}/{1}.csr".format(config.FILE_STORE, normalize_common_name_file(dns_name))

    subj = "/C=/ST=/L=/O=/CN={0}".format(dns_name)
    if order and 'organization' in order:
        subj = "/C={0}/ST={1}/L={2}/O={3}/CN={4}".format(order['organization']['country'], order['organization']['state'].replace(",", ""), order['organization']['city'].replace(",", ""), order['organization']['name'].replace(",", ""), dns_name)
    csr_cmd = 'openssl req -new -newkey rsa:2048 -nodes -out {0} -keyout {1} -subj "{2}" 2>/dev/null'.format(csr_file_name, key_file_name, subj)

    # run the command
    os.system(csr_cmd)

    # verify the existence of the key and csr files
    if not os.path.exists(key_file_name) or not os.path.exists(csr_file_name):
        raise Exception("ERROR: An error occurred while attempting to create your CSR file.  Please try running {0} "
                        "manually and re-run this application with the CSR file location "
                        "as part of the arguments.".format(csr_cmd))
    logger.info("Created private key file {0}...".format(key_file_name))
    logger.info("Created CSR file {0}...".format(csr_file_name))
    print ""
    return key_file_name, csr_file_name

# TODO this could probably use better error handling. For example, if the dns name is simply not found and we get an [Errno -2] Name or service not known
def validate_ssl_success(dns_name):
    logger = loggers.get_logger(__name__)
    # For simply checking that the site is available HTTPSConnection is good enough
    logger.info("Verifying {0} is available over HTTPS...".format(dns_name))
    try:
        conn = HTTPSConnection(dns_name, timeout=10)
        conn.request('GET', '/')
        response = conn.getresponse()
        if str(response.status)[0] == '2':
            logger.info("{0} is reachable over HTTPS".format(dns_name))
            return True
        error = "Application error occurred with status: {0}".format(response.status)
    except Exception as e:
        error = str(e)
    logger.info("There was a problem checking SSL site availability, your site may not be secure: {0}".format(error))
    return False

def validate_private_key(private_key_path, cert_path):
    logger = loggers.get_logger(__name__)
    try:
        private_key_obj = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(private_key_path, 'r').read())
    except OpenSSL.crypto.Error:
        logger.info("Private key path was invalid")
        return False

    try:
        cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(cert_path, 'r').read())
    except OpenSSL.crypto.Error:
        logger.info("Certificate path was invalid")
        return False

    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    context.use_privatekey(private_key_obj)
    context.use_certificate(cert_obj)
    try:
        context.check_privatekey()
        return True
    except OpenSSL.SSL.Error as e:
        logger.debug("Private key and certificate did not match: {0}".format(str(e)))
        logger.info("\033[1mThe private key provided did not match the certificate.\033[0m")
        return False

def set_permission(file_path, user_name, mode=755):
    logger = loggers.get_logger(__name__)
    # change the owners of the ssl files
    logger.info("Making file {0} readable by {1} with mode {2}".format(file_path, user_name, mode))
    os.system("chown root:{0} {1}".format(user_name, file_path))
    # change the permission of the ssl files, only the root and apache users should have read permissions
    os.system("chmod {0} {1}".format(mode, file_path))
