import getpass
import config
import sys
from request import Request
import loggers
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
    dns_names = utils.get_dns_names_from_cert(cert_path) if cert_path else None
    print dns_names
    if domain and not dns_names:
        dns_names = [domain]

    # user manually passed the order id and no dns names were found
    if order_id and not dns_names:
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

    if args.allow_dups:
        if raw_input("Are you trying to install a duplicate certificate? (Y/n) ") == 'y':
            process_duplicate()
    # try to find files matching this domain in /etc/digicert
    # if found, ask to install them

    # otherwise, we need to log in and try to find an order matching this domain
    print "order id {0}".format(order_id)
    print "vhost {0}".format(vhost)
    print "Into the black water"
    try:
        if order_id:
            order = get_order(order_id)
        else:
            orders = get_issued_orders(vhost)
            if not orders:
                # We could push them to order here :p
                raise Exception("No orders found matching that criteria")
            order = select_order(orders)
            order_id = order['id']
        print order
    except Exception as ex:
        print ex
        sys.exit()
    # download certificate, copy files to the right folder

    # Look for existing certificate/chain/key
    # if they are not found, see if an API key exists in config.py
    # if an API key does not exist, log in to get a temporary api key to use for this session
    # if we got here, then we got an api key, get a list of orders

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
        if raw_input("Continue with vhost {0}? (Y/n)".format(hosts[0])) == 'n':
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
        if raw_input("Continue with order #{0} ({1})? (Y/n)".format(orders[0]['id'], orders[0]['certificate']['common_name'])) == 'n':
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
    try:
        main()
        print 'Finished'
    except KeyboardInterrupt:
        print
