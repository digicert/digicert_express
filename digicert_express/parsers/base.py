import augeas
import loggers
import sys
import traceback
import utils
import os
import fnmatch
import shutil
import re
from collections import OrderedDict

class BaseParser(object):
    """ Base parser object.
    """
    directives = dict()

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
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print str(e)
            raise e
            self.check_for_parsing_errors()
            raise Exception("An error occurred while loading your apache configuration.\n{0}".format(str(e)))

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
                vhosts += self.aug.match("{0}/*/*[label()=~regexp('{1}')]".format(host_file, utils.create_regex("VirtualHost")))

                vhost = set(self._get_vhosts_domain_name(vhosts, dns_names=dns_names))
                if vhost:
                    server_virtual_hosts.extend(vhost)
        return server_virtual_hosts

    def _get_vhosts_domain_name(self, vhosts, port=None, dns_names=None, return_paths=False):
        found_domains = []
        for vhost in vhosts:
            if port is None or port in self.aug.get(vhost + "/arg"):
                check_matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]".format(vhost, utils.create_regex("ServerName")))
                if check_matches:
                    for check in check_matches:
                        if self.aug.get(check + "/arg"):
                            aug_domain = self.aug.get(check + "/arg")
                            if dns_names and aug_domain in dns_names:
                                found_domains.append(aug_domain if not return_paths else vhost)
                            elif dns_names:   # Check for wildcard matches
                                for dns_name in dns_names:  # For *.example.com, the vhost ends with .example.com or equals example.com
                                    if (dns_name[:2] == '*.') and (dns_name[1:] == aug_domain[1-len(dns_name):] or dns_name[2:] == aug_domain):
                                        found_domains.append(aug_domain if not return_paths else vhost)
                                        break
                            else:   # There is no dns_name filter, return everything.
                                found_domains.append(aug_domain if not return_paths else vhost)
        return found_domains

    def get_vhost_path_by_domain(self, dns_name):
        vhost = None
        matches = self.aug.match("/augeas/load/Httpd/incl")
        for match in matches:
            host_file = "/files{0}".format(self.aug.get(match))
            if '~previous' not in host_file:
                vhosts = self.aug.match("{0}/*[label()=~regexp('{1}')]".format(host_file, utils.create_regex("VirtualHost")))
                vhosts += self.aug.match("{0}/*/*[label()=~regexp('{1}')]".format(host_file, utils.create_regex("VirtualHost")))
                match_vhosts = self._get_vhosts_domain_name(vhosts, '443', [dns_name], return_paths=True)
                if not match_vhosts:
                    match_vhosts = self._get_vhosts_domain_name(vhosts, '80', [dns_name], return_paths=True)
                    if match_vhosts:
                        # we didn't find an existing 443 virtual host but found one on 80
                        # create a new virtual host for 443 based on 80
                        vhost = self._create_secure_vhost(match_vhosts[0])
                else:
                    vhost = match_vhosts[0]

                # if the vhost got set above, then we should return it because we found a match. However, it might not have been found in this iteration
                if vhost:
                    return vhost
        return None

    def _create_secure_vhost(self, vhost):
        self.logger.info("Creating new virtual host {0} on port 443".format(vhost))
        secure_vhost = None
        host_file = "/files{0}".format(self.get_path_to_file(vhost))

        # create a map of the insecure vhost's configuration
        vhost_map = list()
        self._create_map_from_vhost(vhost, vhost_map)

        # only add the IfModule section if the platform supports it
        if self.platform.include_ifmodule():
            # check if there is an IfModule for mod_ssl.c, if not create it
            if_module = None
            check_matches = self.aug.match("{0}/*[label()=~regexp('{1}')]".format(host_file, utils.create_regex("IfModule")))
            if check_matches:
                for check in check_matches:
                    if self.aug.get(check + "/arg") == "mod_ssl.c":
                        if_module = check
            if not if_module:
                self.aug.set(host_file + "/IfModule[last()+1]/arg", "mod_ssl.c")
                if_modules = self.aug.match(host_file + "/*[self::IfModule/arg='mod_ssl.c']")
                if len(if_modules) > 0:
                    if_module = if_modules[0]
                    host_file = if_module
                else:
                    raise Exception("An error occurred while creating IfModule mod_ssl.c for {0}.".format(vhost))

        # FIXME we may be able to improve this in the case where multiple secure vhosts are already in the config file
        # create a new secure vhost
        vhost_name = self.aug.get(vhost + "/arg")
        vhost_name = vhost_name[0:vhost_name.index(":")] + ":443"
        self.aug.set(host_file + "/VirtualHost[last()+1]/arg", vhost_name)

        # this should return an array of exactly one item: the secure vhost directive we just added to the current config file
        vhosts = self.aug.match("{0}/*[self::VirtualHost/arg='{1}']".format(host_file, vhost_name))
        for vhost in vhosts:
            secure_vhost = vhost

            # write the existing vhost configuration under the new secure vhost directive we found
            self._create_vhost_from_map(secure_vhost, vhost_map)

        self.check_for_parsing_errors()

        return secure_vhost

    def get_path_to_file(self, path):
        """
        Take an augeas path (ie: /files/etc/apache2/apache2.conf/VirtualHost/Directory/) and return the path
        to the apache configuration file (ie: /etc/apache2/apache2.conf)

        :param path
        :return: path to an actual file or None
        """
        if "/files/" in path[:7]:
            path = path[6:]

        while not os.path.exists(path) and not os.path.isdir(path):
            last_slash_index = path.rfind("/")
            if last_slash_index > 0:
                path = path[:last_slash_index]
            else:
                return None
        return path

    def _create_map_from_vhost(self, path, vhost_map, text=""):
        # recurse through the directives and sub-groups to generate a map
        check_matches = self.aug.match(path + "/*")
        if check_matches:
            for check in check_matches:
                values = list()
                # get the type of configuration
                config_type = check[len(path)+1:]
                config_name = self.aug.get(check)
                config_value = self.aug.get(check + "/arg")

                if "arg" not in config_type and "#comment" not in config_type:
                    # check if we have a config_value, if we don't its likely that there are multiple
                    # values rather than just one and we need to get them via aug.match
                    if not config_value:
                        arg_check_matches = self.aug.match("{0}/{1}/arg".format(path, config_type))
                        for arg_check in arg_check_matches:
                            values.append(self.aug.get(arg_check))
                            if config_value:
                                config_value += " {0}".format(self.aug.get(arg_check))
                            else:
                                config_value = self.aug.get(arg_check)
                    else:
                        values.append(config_value)

                    # check for config_name, if we don't then this a sub-group and not a directive
                    if not config_name:
                        # this is a sub-group, recurse
                        sub_map = list()
                        vhost_map.append({'type': config_type, 'name': None, 'values': values, 'sub_group': sub_map})
                        self._create_map_from_vhost(path + "/" + config_type, sub_map, "{0}\t".format(text))
                    else:
                        vhost_map.append({'type': config_type, 'name': config_name, 'values': values, 'sub_group': None})

    def _create_vhost_from_map(self, path, vhost_map, text=""):
        # recurse through the map and write the new vhost
        for entry in vhost_map:
            config_type = entry['type']
            config_name = entry['name']
            config_values = entry['values']
            config_sub = entry['sub_group']

            value = None
            for v in config_values:
                if not value:
                    value = v
                else:
                    value += " {0}".format(v)

            self.aug.set("{0}/{1}".format(path, config_type), config_name)

            if len(config_values) > 1:
                i = 1
                for value in config_values:
                    self.aug.set("{0}/{1}/arg[{2}]".format(path, config_type, i), value)
                    i += 1
            else:
                self.aug.set("{0}/{1}/arg".format(path, config_type), value)

            if not config_name and config_type and config_sub:
                # this is a sub-group, recurse
                sub_groups = self.aug.match("{0}/{1}".format(path, config_type))
                for sub_group in sub_groups:
                    self._create_vhost_from_map(sub_group, config_sub, "{0}\t".format(text))

    def set_certificate_directives(self, vhost_path, dns_name):
        try:
            if not vhost_path:
                raise Exception("Virtual Host was not found for {0}.  Please verify that the 'ServerName' directive in "
                                "your Virtual Host is set to {1} and try again.".format(dns_name, dns_name))

            # back up the configuration file
            host_file = self.get_path_to_file(vhost_path)
            shutil.copy(host_file, "{0}~previous".format(host_file))

            errors = []
            for directive in self.directives:
                matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]".format(vhost_path, utils.create_regex(directive)))
                if len(matches) > 0:
                    for match in matches:
                        self.aug.set("{0}/arg".format(match), self.directives[directive])
                        self.logger.info("Directive {0} was updated to {1} in {2}".format(directive, self.directives[directive], match))
                else:
                    self.aug.set(vhost_path + "/directive[last()+1]", directive)
                    self.aug.set(vhost_path + "/directive[last()]/arg", self.directives[directive])

            if len(errors):
                error_msg = "Could not update all directives:\n"
                for error in errors:
                    error_msg = "{0}\t{1}\n".format(error_msg, error)
                raise Exception(error_msg)

            self.aug.save()

            # check for augeas errors
            self.check_for_parsing_errors()

            # verify the added/modified directives are the values we set
            errors = []
            for directive in self.directives:
                val = None
                matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]/arg".format(vhost_path, utils.create_regex(directive)))
                if len(matches) > 0:
                    for match in matches:
                        val = self.aug.get(match)

                if val != self.directives[directive]:
                    errors.append("{0} is {1} instead of {2}".format(directive, val, self.directives[directive]))

            if len(errors) > 0:
                error_msg = "Some of your directives are incorrect:\n"
                for error in errors:
                    error_msg = "{0}\t{1}\n".format(error_msg, error)
                raise Exception(error_msg)

        except Exception, e:
            self.check_for_parsing_errors()
            raise Exception("An error occurred while updating the Virtual Host for {0}: {1}".format(dns_name, str(e)))

        # format the file:
        try:
            self.format_config_file(host_file)
        except Exception as e:
            raise Exception("The changes have been made but there was an error occurred while formatting your file:\n{0}".format(str(e)))

        # verify that augeas can still load the changed file
        self.aug.load()

    def format_config_file(self, host_file):
        """
        Format the apache configuration file.  Loop through the lines of the file and indent/un-indent where necessary

        :param host_file:
        :return:
        """
        self.logger.info("Formatting file {0}".format(host_file))

        # get the lines of the config file
        lines = list()
        with open(host_file) as f:
            lines = f.read().splitlines()

        f = open(host_file, 'w+')

        try:
            self.format_lines(lines, f)
        finally:
            f.truncate()
            f.close()

    def format_lines(self, lines, f):
        tabs = ""
        for line in lines:
            line = line.lstrip()
            # check for the beginning of a tag, if found increase the indentation after writing the tag
            if re.match("^<(\w+)", line):
                f.write("{0}{1}\n".format(tabs, line))
                tabs += "\t"
            else:
                # check for the end of a tag, if found decrease the indentation
                if re.match("^</(\w+)", line):
                    if len(tabs) > 1:
                        tabs = tabs[:-1]
                    else:
                        tabs = ""
                # write the config/tag
                f.write("{0}{1}\n".format(tabs, line))

    def preinstall_setup(self, cert_path, intermediate_path, pk_path):
        self.directives = OrderedDict()
        self.directives['SSLEngine'] = "on"
        self.directives['SSLCertificateFile'] = cert_path
        self.directives['SSLCertificateKeyFile'] = pk_path
        self.directives['SSLCertificateChainFile'] = intermediate_path

    def install_certificate(self, dns_name):
        self.logger.info("Configuring Web Server for virtual host: {0}".format(dns_name))

        virtual_host = self.get_vhost_path_by_domain(dns_name)
        self.set_certificate_directives(virtual_host, dns_name)
        self.platform.enable_ssl_mod()

        self.logger.info('Apache configuration updated successfully.')
