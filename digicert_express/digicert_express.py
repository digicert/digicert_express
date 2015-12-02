import getpass
import config
import sys
from request import Request
import loggers
import json
import argparse
import utils
from parsers import base as base_parser
from platforms import centos_platform, ubuntu_platform

def main():
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
    platform = None
    # TODO maybe have determine_platform return the platform object instead of doing it this way.
    dist = utils.determine_platform()
    if dist[0] == "CentOS":
        platform = centos_platform.CentosPlatform()
    else:
        platform = ubuntu_platform.UbuntuPlatform()

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
        if len(order['certificate']['dns_names']) > 1:
            dns_names = order['certificate']['dns_names']
        else:
            dns_names = [order['certificate']['common_name']]
        order_id = order['id']

    if order and order['status'] == 'needs_csr':
        private_key_file, csr_file = utils.create_csr(dns_name=vhost, order=order)
        upload_csr(order_id, csr_file)
        order = get_order(order_id)
        if order['status'] == 'issued':
            pass  # download cert

    if not private_key_file:
        # go and find the private key
        # if not found...
        if args.allow_dups:
            if raw_input("Are you trying to install a duplicate certificate? (Y/n) ") == 'y':
                order = get_order(order_id) if not order else order
                private_key_file, csr_file = utils.create_csr(dns_name=vhost, order=order)
                dup_data = create_duplicate(order=order, csr_file=csr_file)
                if not dup_data['sub_id']:
                    raise Exception("DOH")
        # require a file path to the private key

    if not cert_path:
        # go and find the certificate file
        # if not found and we have an order_id, ask if they want to download the certificate
        # if they don't, require a file path to the cert file
        # if they do, download it and copy the files to the right folder
        pass

    if cert_path and private_key_file:
        # validate the private key is for the certificate we have
        # if they don't match, exception
        # if they match, copy them to the right place with the intermediate
        pass


# TODO consider moving API request calls to their own file (api.py maybe?)
def create_duplicate(order, csr_file):
    logger = loggers.get_logger(__name__)
    csr_text = None
    with open(csr_file, "r") as f:
        csr_text = f.read()
    # TODO consider changing common name to vhost if we need to or can
    cert_data = {"certificate": {"common_name": order['certificate']['common_name'], "csr": csr_text, "signature_hash": order['certificate']['signature_hash'], "server_platform": {"id": 2}, "dns_names": order['certificate']['dns_names']}}
    logger.debug("Submitting request for duplicate on order #{0} with data {1}".format(order['id'], json.dumps(cert_data)))
    r = Request().post('/order/{0}/duplicate'.format(order['id']), cert_data)
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
    r = Request().post('/order/{0}/csr', {'csr': csr_text})
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
            if domain_filter not in order['certificate']['dns_names']:
                continue
        orders.append(order)
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
