import augeas
import loggers
import sys
import traceback
import utils
import os
import fnmatch

class BaseParser(object):
    """ Base parser object.
    """

    def __init__(self, platform, aug=None, autoload=True):
        self.logger = loggers.get_logger(__name__)
        if not aug:
            my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
            aug = augeas.Augeas(flags=my_flags)
        self.aug = aug
        self.platform = platform
        if autoload:
            self.load_apache_configs()

    def load_apache_configs(self, apache_config_file=None):
        try:
            if not apache_config_file:
                apache_config_file = self.platform.find_apache_config()
            self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
            if apache_config_file:
                self.aug.set("/augeas/load/Httpd/incl", apache_config_file)
                self.aug.load()

                # get all of the included configuration files and add them to augeas
                self.logger.info("Loading Apache configuration files...")
                self._load_included_files(apache_config_file)
                self.check_for_parsing_errors()
            else:
                raise Exception("We could not find your main apache configuration file.  Please ensure that apache is "
                                "running or include the path to your virtual host file in your command line arguments")
        except Exception, e:
            traceback.print_exc(file=sys.stdout)
            print e.message
            raise e
            self.check_for_parsing_errors()
            raise Exception(
                "An error occurred while loading your apache configuration.\n{0}".format(e.message),
                self.directives)

    def _load_included_files(self, apache_config):
        # get the augeas path to the config file
        apache_config = "/files{0}".format(apache_config)

        incl_regex = "({0})|({1})".format(utils.create_regex('Include'), utils.create_regex('IncludeOptional'))
        includes = self.aug.match(("{0}//* [self::directive=~regexp('{1}')]/* [label()='arg']".format(apache_config, incl_regex)))

        # If there are files included from the standard httpd configs, add them to Augeas so we can change them
        if includes:
            for include in includes:
                include_file = self.aug.get(include)

                if include_file:
                    if include_file[0] != "/":
                        include_file = os.path.join(os.path.dirname(apache_config[6:]), include_file)

                    if "*" not in include_file and include_file[-1] != "/":
                        self.aug.set("/augeas/load/Httpd/incl [last()+1]", include_file)
                        self.aug.load()
                        self._load_included_files(include_file)
                    else:
                        if include_file[-1] == "/":
                            include_file += "*"
                        if "*" in include_file:
                            config_dir = os.path.dirname(include_file)
                            file_exp = include_file[include_file.index(config_dir) + len(config_dir) + 1:]
                            for file in os.listdir(config_dir):
                                if fnmatch.fnmatch(file, file_exp):
                                    config_file = os.path.join(config_dir, file)
                                    self.aug.set("/augeas/load/Httpd/incl [last()+1]", config_file)
                                    self.aug.load()
                                    self._load_included_files(config_file)

    def check_for_parsing_errors(self):
        self.logger.info("Verifying Apache configuration files can be parsed...")
        errors = []
        error_files = self.aug.match("/augeas//error")
        for path in error_files:
            # check to see if it was an error resulting from the use of the httpd lens
            lens_path = self.aug.get(path + "/lens")
            if lens_path and "httpd.aug" in lens_path:
                # strip off /augeas/files and /error
                error_message = self.aug.get(path + "/message")
                error_line = self.aug.get(path + "/line")

                errors.append("Error parsing the file: {0} {1} at line #{2}".format(
                    path[13:len(path) - 6], error_message, error_line))

        if len(errors) > 0:
            error_msg = "The following errors occurred while parsing your configuration file:"
            for error in errors:
                error_msg = "{0}\t{1}\n".format(error_msg, error)
            raise Exception(error_msg)

    def get_vhosts_on_server(self, dns_names=None):
        """ Use this method to search for all virtual hosts configured on the web server """
        self.logger.info("Getting vhosts on server")
        server_virtual_hosts = []
        matches = self.aug.match("/augeas/load/Httpd/incl")
        for match in matches:
            host_file = "/files{0}".format(self.aug.get(match))
            if '~previous' not in host_file:
                vhosts = self.aug.match("{0}/*[label()=~regexp('{1}')]".format(host_file, utils.create_regex("VirtualHost")))
                vhosts += self.aug.match("{0}/*/*[label()=~regexp('{1}/arg')]".format(host_file, utils.create_regex("VirtualHost")))

                vhost = self._get_vhosts_domain_name(vhosts, '443', dns_names)
                if not vhost:
                    vhost = self._get_vhosts_domain_name(vhosts, '80', dns_names)
                if vhost:
                    server_virtual_hosts.extend(vhost)
        return server_virtual_hosts

    def _get_vhosts_domain_name(self, vhosts, port, dns_names):
        found_domains = []
        for vhost in vhosts:
            check_matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]".format(vhost, utils.create_regex("ServerName")))
            if check_matches:
                for check in check_matches:
                    if self.aug.get(check + "/arg"):
                        aug_domain = self.aug.get(check + "/arg")
                        if dns_names and aug_domain in dns_names:  # TODO This does not work for wildcards yet...
                            found_domains.append(aug_domain)
                        else:   # Check for wildcard matches
                            for dns_name in dns_names:  # For *.example.com, the vhost ends with .example.com or equals example.com
                                if (dns_name[:2] == '*.') and (dns_name[1:] == aug_domain[1-len(dns_name):] or dns_name[2:] == aug_domain):
                                    found_domains.append(aug_domain)
                                    break
        return found_domains
