import os
import loggers
import config
import subprocess

# This class defaults to Debian values
class BasePlatform():
    APACHE_SERVICE = 'apache2ctl'
    APACHE_RESTART_COMMAND = '/etc/init.d/apache2 restart'
    APACHE_PROCESS_NAME = 'apache2'
    DEPS = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'openssl', 'python-pip', 'python-openssl']

    def __init__(self):
        self.logger = loggers.get_logger(__name__)

    def find_apache_config(self):
        """
        This should return a path to the apache configuration file (i.e. /etc/apache2/apache2.conf)
        """
        apache_command = "`which {0}` -V 2>/dev/null".format(self.APACHE_SERVICE)
        apache_config = os.popen(apache_command).read()
        if apache_config:
            server_config_check = "SERVER_CONFIG_FILE="
            httpd_root_check = "HTTPD_ROOT="
            # ex:   -D SERVER_CONFIG_FILE="conf/httpd.conf"\n
            server_config_file = [cfg_item for cfg_item in apache_config.split('\n') if server_config_check in cfg_item][0].split('=')[1].replace('"', '')

            if server_config_file[0] != "/":
                # get the httpd root to find the server config file path
                self.logger.info("Finding Apache configuration files...")
                # ex:   -D HTTPD_ROOT="/etc/httpd"\n
                httpd_root_dir = [cfg_item for cfg_item in apache_config.split('\n') if httpd_root_check in cfg_item][0].split('=')[1].replace('"', '')
                if os.path.isdir(httpd_root_dir):
                    server_config_file = os.path.join(httpd_root_dir, server_config_file)

            if os.path.isfile(server_config_file):
                return server_config_file

    def check_dependencies(self):
        try:
            self.logger.info("Checking for required dependencies")
            import apt
            a = apt.cache.Cache(memonly=True)

            installed_packages = []
            ignored_packages = []
            for package_name in self.DEPS:
                if a[package_name].is_installed:
                    continue
                else:
                    if raw_input('Install: {0} (Y/n) '.format(package_name)).lower().strip() == 'n':
                        ignored_packages.append(package_name)
                        continue
                    else:
                        self.logger.info("Installing package {0}...".format(package_name))
                        os.system('apt-get -y install {0} &>> {1}'.format(a[package_name].name, config.LOG_FILE))
                        installed_packages.append(package_name)
                        continue
            if not installed_packages and not ignored_packages:
                self.logger.info("All dependencies are met.")
            return ignored_packages
        except ImportError:
            pass

    def restart_apache(self):
        self.logger.info("Restarting your apache server")
        subprocess.call(self.APACHE_RESTART_COMMAND, shell=True)
        success = self.check_for_apache_process()

        if success:
            self.logger.info('Apache restarted successfully.')

        return success

    # TODO maybe this doesn't need to be a separate function from the above...
    def check_for_apache_process(self):
        error = "Unknown error"
        try:
            process = os.popen("ps aux | grep {0}".format(self.APACHE_PROCESS_NAME)).read().splitlines()
            self.logger.debug("Looking for {0} processes and found {1}".format(self.APACHE_PROCESS_NAME, ", ".join(process)))
            if len(process) > 2:
                return True
        except Exception as e:
            error = str(e)
        self.logger.error("Problem restarting apache: {0}".format(error))
        return False

    def get_apache_user(self):
        command = "ps aux | egrep '{0}' | grep -v `whoami` | grep -v root | head -n1 | awk '{{print $1}}'".format(self.APACHE_PROCESS_NAME)
        return os.popen(command).read().strip()

    def include_ifmodule(self):
        return True

    def enable_ssl_mod(self):
        self.logger.info('Enabling Apache SSL module...')
        if not self._is_ssl_mod_enabled():
            try:
                subprocess.check_call(["sudo", 'a2enmod', 'ssl'], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'), shell=True)
            except (OSError, subprocess.CalledProcessError) as e:
                self.logger.debug("An exception happened: {0}".format(str(e)))
                raise Exception("There was a problem enabling mod_ssl.  Run 'sudo a2enmod ssl' to enable it or check the apache log for more information")

    def _is_ssl_mod_enabled(self):
        try:
            proc = subprocess.Popen([self.APACHE_SERVICE, '-M'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except:
            raise Exception("There was a problem accessing '{0}'".format(self.APACHE_SERVICE))

        if 'ssl' in stdout:
            return True
        return False
