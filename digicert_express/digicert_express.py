import getpass
import config
import sys
from request import Request
import loggers
import json
import argparse
import utils
import os
from parsers import base as base_parser
import readline
import shutil

readline.parse_and_bind('tab: complete')
readline.parse_and_bind('set editing-mode vi')

def main():
    # TODO make sure we are running with sudo/root privileges
    # accept arguments
    parser = argparse.ArgumentParser(description='Download your certificate and secure your domain in one step')
    parser.add_argument("--order_id", action="store", help="DigiCert order ID for certificate")
    parser.add_argument("--cert_path", action="store", help="the path to the certificate file")
    parser.add_argument("--domain", action="store", help="Domain name to secure")
    parser.add_argument("--key", action="store", help="Path to private key file used to order certificate")
    parser.add_argument("--api_key", action="store", help="Skip authentication step with a DigiCert API key")
    parser.add_argument("--sub_id", action="store", help="Duplicate key")
    parser.add_argument("--allow_dups", action="store", help="a flag to indicate whether the order type allows duplicates mostly for convenience")

    args = parser.parse_args()

    order_id = args.order_id
    domain = args.domain
    if args.api_key:
        config.API_KEY = args.api_key
    cert_path = args.cert_path

    # get platform class and check platform level dependencies
    platform = utils.determine_platform()

    ignored_packages = platform.check_dependencies()
    if ignored_packages:
        raise Exception("You will need to install these packages before continuing: {0}".format(",".join(ignored_packages)))

    # user tried to manually pass a domain name without an order id. No workie.
    if not order_id and domain:
        raise Exception("You cannot use this tool this way. Please visit the website and download an installer from your order details page.")

    # get the dns names from the cert if one was passed in
    dns_names = utils.get_dns_names_from_cert(cert_path)

    order = None

    # user manually passed the order id and no dns names were found
    if order_id and not dns_names:
        cert_path = None  # the cert_path was invalid
        order = get_order(order_id)
        if len(order['certificate']['dns_names']) > 1:
            dns_names = order['certificate']['dns_names']
        else:
            dns_names = [order['certificate']['common_name']]

    aug = base_parser.BaseParser(platform=platform)
    hosts = aug.get_vhosts_on_server(dns_names)

    if not hosts:
        raise Exception("No virtual hosts were found on this server that will work with your certificate")

    if len(hosts) > 1:
        vhost = select_vhost(hosts)
    else:
        if raw_input("The host {0} was found matching this certificate. Is this correct? (Y/n) ".format(hosts[0])).lower().strip() != "y":
            raise Exception("No virtual hosts were found on this server that will work with your certificate")
        vhost = hosts[0]

    # We should only go through this if block when the script is run without an order_id and cert_path
    if not dns_names:
        orders = get_issued_orders(vhost)
        if not orders:
            # We could push them to order here :p
            raise Exception("No orders found matching that criteria")
        order = select_order(orders)
        # TODO this right here?
        order = get_order(order['id'])
        order_id = order['id']

    private_key_file = None
    private_key_matches_cert = False

    # see if the order needs to have a csr uploaded
    if order and order['status'] == 'needs_csr':
        # TODO do we want to try to find an existing csr?
        private_key_file, csr_file = utils.create_csr(dns_name=vhost, order=order)
        upload_csr(order_id, csr_file)
        order = get_order(order_id)
        if order['status'] == 'issued':
            certs = download_certificate(order)
            cert_path = utils.save_certs(certs, vhost)
            private_key_matches_cert = True

    # TODO perform very basic searches for the PK and cert files based on where we would have stored them (including the order_id and sub_id)
    if not private_key_file:
        #private_key_file = locate_pk()
        pass
    if not cert_path:
        #cert_path = locate_cert()
        pass

    while not private_key_matches_cert:
        if not private_key_file:
            if args.allow_dups or (order and order['allow_duplicates'] == 1):
                print "\033[1mDuplicates require permission to approve requests on this order.\033[0m"
                if raw_input("Are you trying to install a duplicate certificate? (Y/n) ") == 'y':
                    order = get_order(order_id) if not order else order
                    private_key_file, csr_file = utils.create_csr(dns_name=vhost, order=order)
                    dup_data = create_duplicate(order=order, csr_file=csr_file)
                    if not 'sub_id' in dup_data:
                        approve_request(dup_data['requests'][0]['id'])
                        duplicates = get_duplicates(order['id'])
                        if not duplicates:
                            raise Exception("Could not collect any duplicates for this order")
                        order['sub_id'] = duplicates['certificates'][0]['sub_id']
                    else:
                        order['sub_id'] = dup_data['sub_id']
                    if not order['sub_id']:
                        raise Exception("Something went wrong")
                    certs = download_certificate(order)
                    cert_path = utils.save_certs(certs, vhost)
                    private_key_matches_cert = True
                    continue
            # Cert does not allow duplicates, or the user chose no (still missing private_key_file)
            pk_path = None
            while not private_key_file or pk_path != "q":
                pk_path = raw_input("please provide the path to the private key for this certificate: (q to quit) ")
                if pk_path == "q":
                    raise Exception("Cannot install the certificate without a private key file")
                if not os.path.isfile(pk_path):
                    logger.info("The path {0} is not a valid file. Please try again.")
                    continue
                private_key_file = pk_path
        if not cert_path:
            certs = download_certificate(order)
            cert_path = utils.save_certs(certs, vhost)
        private_key_matches_cert = validate_private_key(private_key_file, cert_path)
        if not private_key_matches_cert:
            print "\033[1mThe private key provided did not match the certificate.\033[0m"
            private_key_file = None
        elif config.FILE_STORE not in private_key_file:
            new_private_key_file = "{0}/{1}/{1}.key".format(config.FILE_STORE, utils.normalize_common_name_file(vhost))
            shutil.copyfile(private_key_file, new_private_key_file)
            private_key_file = new_private_key_file

    # Sanity check
    if not cert_path or not private_key_file:
        raise Exception("Something bad happened. We shouldn't have been able to get here")

    # install in apache
    # restart apache
    # verify that the existing site responds to https afterwards


def validate_private_key(private_key_path, cert_path):
    key_command = "openssl rsa -noout -modulus -in \"{0}\" | openssl md5".format(private_key_path)
    crt_command = "openssl x509 -noout -modulus -in \"{0}\" | openssl md5".format(cert_path)

    key_modulus = os.popen(key_command).read()
    crt_modulus = os.popen(crt_command).read()

    return key_modulus == crt_modulus


# TODO consider moving API request calls to their own file (api.py maybe?)
def download_certificate(order):
    logger = loggers.get_logger(__name__)
    check_credential()
    logger.debug("Downloading certificate")
    # TODO this distinction shouldn't exist here
    if 'certificate_id' in order and order['certificate_id']:  # for cert central accounts
        r = Request(raw_file=True).get('/certificate/{0}/download/format/pem_all'.format(order['id']))
    else:  # for mpki/retail accounts
        params = {"format_type": "pem_all"}
        if 'sub_id' in order and order['sub_id']:
            params["sub_id"] = order['sub_id']
        r = Request(raw_file=True).get('/certificate/download/order/{0}'.format(order['id']), params)
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Downloaded certificate for order #{0}".format(order['id']))
    certs = r.data.split("-----BEGIN")  # 0 - empty, 1 - cert, 2 - intermediate, 3 - root... do we need root?
    return {
        "certificate": "-----BEGIN{0}".format(certs[1]),
        "intermediate": "-----BEGIN{0}".format(certs[2]),
    }


def get_duplicates(order_id):
    logger = loggers.get_logger(__name__)
    check_credential()
    logger.debug("Getting list of duplicates from API")
    r = Request().get('/order/certificate/{0}/duplicate'.format(order_id))
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Collected {0} duplicates for order_id {1}".format(len(r.data), order_id))
    return r.data

def approve_request(request_id):
    logger = loggers.get_logger(__name__)
    check_credential()
    data = {"status": "approved", "processor_comment": "Automatically approved by Express Install"}
    logger.debug("Submitting approval to the API")
    r = Request().put('/request/{0}/status'.format(request_id), data)
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Approval succeeded with response [{0}] {1}".format(r.status_code, json.dumps(r.data) if r.data else "No response"))
    return r.data

def create_duplicate(order, csr_file):
    logger = loggers.get_logger(__name__)
    check_credential()
    csr_text = None
    with open(csr_file, "r") as f:
        csr_text = f.read()
    # TODO consider changing common name to vhost if we need to or can
    cert_data = {"certificate": {"common_name": order['certificate']['common_name'], "csr": csr_text, "signature_hash": order['certificate']['signature_hash'], "server_platform": {"id": 2}, "dns_names": order['certificate']['dns_names']}}
    logger.debug("Submitting request for duplicate on order #{0} with data {1}".format(order['id'], json.dumps(cert_data)))
    r = Request().post('/order/certificate/{0}/duplicate'.format(order['id']), cert_data)
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Duplicate request succeeded with response {0}".format(json.dumps(r.data)))
    return r.data

def upload_csr(order_id, csr_file):
    logger = loggers.get_logger(__name__)
    check_credential()
    csr_text = None
    logger.debug("Reading CSR from file at {0}".format(csr_file))
    with open(csr_file, "r") as f:
        csr_text = f.read()
    r = Request().post('/order/certificate/{0}/csr'.format(order_id), {'csr': csr_text})
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.info("Updated CSR on order #{0}".format(order_id))

def get_issued_orders(domain_filter=None):
    logger = loggers.get_logger(__name__)
    check_credential()
    filters = '?filters[status]=issued'
    r = Request().get('/order/certificate{0}'.format(filters))
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Collected order list with {0} orders".format(len(r.data['orders'])))
    orders = []
    for order in r.data['orders']:
        if domain_filter:
            if domain_filter in order['certificate']['dns_names']:
                orders.append(order)
            else:   # Check for wildcard matches
                for dns_name in order['certificate']['dns_names']:  # For dns_name *.example.com, the domain_filter ends with .example.com or equals example.com
                    if (dns_name[:2] == '*.') and (dns_name[1:] == domain_filter[1-len(dns_name):] or dns_name[2:] == domain_filter):
                        orders.append(order)
                        break

    logger.debug("Returning {0} orders after filtering".format(len(orders)))
    return orders

def get_order(order_id):
    logger = loggers.get_logger(__name__)
    check_credential()
    r = Request().get('/order/certificate/{0}'.format(order_id))
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        else:
            logger.error("Server returned an error condition: {0}".format(r.get_message()))
            sys.exit()
    logger.debug("Returning order #{0}".format(r.data['id']))
    return r.data

def select_vhost(hosts):
    response = None
    if hosts and len(hosts) > 1:
        while not response or response == "" or response.isalpha():
            i = 1
            for host in hosts:
                print "{0}.\t{1}".format(i, host)
                i += 1
            response = raw_input("\nPlease choose a domain to secure from the list above (q to quit): ")
            if response == 'q':
                raise Exception("No domain selected; aborting.")
            else:
                try:
                    if int(response) > len(hosts) or int(response) < 1:
                        raise Exception
                except Exception:
                    response = None
                    print ""
                    print "ERROR: Invalid response, please try again."
                    print ""
        return hosts[int(response)-1]
    elif hosts and len(hosts) == 1:
        if raw_input("Continue with vhost {0}? (Y/n) ".format(hosts[0])) == 'n':
            raise Exception("User canceled; aborting.")
        return hosts[0]
    else:
        raise Exception("Could not find any unsecured hosts, please add an insecure host for us to modify and try again")

def select_order(orders):
    response = None
    if orders and len(orders) > 1:
        while not response or response == "" or response.isalpha():
            i = 1
            for order in orders:
                print "{0}.\t#{1} ({2}) Expires: {3}".format(i, order['id'], order['certificate']['common_name'], order['certificate']['valid_till'])
                i += 1
            response = raw_input("\nPlease choose an order to secure this vhost with from the list above (q to quit): ")
            if response == 'q':
                raise Exception("No order selected; aborting.")
            else:
                try:
                    if int(response) > len(orders) or int(response) < 1:
                        raise Exception
                except Exception:
                    response = None
                    print ""
                    print "ERROR: Invalid response, please try again."
                    print ""
        return orders[int(response)-1]
    elif orders and len(orders) == 1:
        if raw_input("Continue with order #{0} ({1})? (Y/n) ".format(orders[0]['id'], orders[0]['certificate']['common_name'])) == 'n':
            raise Exception("User canceled; aborting.")
        return orders[0]
    else:
        raise Exception("Could not find any orders, please visit the website and download an installer from your order details page")

def do_everything_with_args(order_id='', domain='', api_key='', key=''):
    raw_input("I'll attempt to secure virtual hosts configured on this web server with an SSL certificate.  Press ENTER to continue.")
    print ''

def check_credential():
    if not config.API_KEY:
        config.API_KEY = request_login()

def request_login():
    logger = loggers.get_logger(__name__)
    # do you have a DigiCert api key? <y>
    logger.info("Please login to continue.")
    username = raw_input("DigiCert Username: ")
    password = getpass.getpass("DigiCert Password: ")

    r = Request().post('/user/tempkey', {'username': username, 'current_password': password})
    if r.has_error:
        # This is an unrecoverable error. We can't see the API for some reason
        if r.is_response_error():
            logger.error('Server request failed. Unable to access API.')
            sys.exit()
        logger.debug('Authentication failed with username {0}'.format(username))
        if raw_input('Authentication failed! Would you like to try again? [y/n] ') != 'n':
            return request_login()
        else:
            logger.error("Authentication failed. Unable to continue.")
            sys.exit()
    return r.data["api_key"]

if __name__ == '__main__':
    logger = loggers.get_logger(__name__)
    try:
        main()
        print 'Finished'
    except Exception as ex:
        logger.debug("Expectedly ended operation with message: {0}".format(ex))
        print ex
    except KeyboardInterrupt:
        print
