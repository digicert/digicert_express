import loggers
import platform
import re
import os
import config
from httplib import HTTPSConnection
from platforms import centos_platform, ubuntu_platform

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

def save_certs(certs, dns_name):
    # TODO should we add the order_id and sub_id to always make this unique?
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
    command = "sudo openssl x509 -in {0} -text -noout | sed -nr '/^ {{12}}X509v3 Subject Alternative Name/{{n; s/(^|,) *DNS:/,/g; s/(^|,) [^,]*//g;p}}'".format(cert_path)
    dns_names_result = os.popen(command).read()
    dns_names = dns_names_result.split(',')
    dns_names = [x for x in dns_names if x]
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
    key_command = "openssl rsa -noout -modulus -in \"{0}\" | openssl md5".format(private_key_path)
    crt_command = "openssl x509 -noout -modulus -in \"{0}\" | openssl md5".format(cert_path)

    logger.info("Verifying private key matches certificate...")
    key_modulus = os.popen(key_command).read()
    crt_modulus = os.popen(crt_command).read()

    return key_modulus == crt_modulus

def set_permission(file_path, user_name, mode=755):
    logger = loggers.get_logger(__name__)
    # change the owners of the ssl files
    logger.info("Making file {0} readable by {1} with mode {2}".format(file_path, user_name, mode))
    os.system("chown root:{0} {1}".format(user_name, file_path))
    # change the permission of the ssl files, only the root and apache users should have read permissions
    os.system("chmod {0} {1}".format(mode, file_path))
