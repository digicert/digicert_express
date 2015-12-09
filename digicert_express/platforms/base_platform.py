import os
import loggers
import config
import subprocess

# This class defaults to Debian values
class BasePlatform():
    APACHE_SERVICE = 'apache2ctl'
    APACHE_RESTART_COMMAND = '/etc/init.d/apache2 restart'
    APACHE_PROCESS_NAME = 'apache2'
    DEPS = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'openssl', 'python-pip']

    def __init__(self):
        self.logger = loggers.get_logger(__name__)

    def find_apache_config(self):
        apache_command = "`which {0}` -V 2>/dev/null".format(self.APACHE_SERVICE)
        apache_config = os.popen(apache_command).read()
        if apache_config:
            server_config_check = "SERVER_CONFIG_FILE="
            httpd_root_check = "HTTPD_ROOT="
            server_config_file = apache_config[apache_config.index(server_config_check) + len(server_config_check): -1]
            server_config_file = server_config_file.replace('"', '')

            if server_config_file[0] != "/":
                # get the httpd root to find the server config file path
                self.logger.info("Finding Apache configuration files...")
                httpd_root_dir = apache_config[apache_config.index(httpd_root_check) + len(httpd_root_check): -1]
                httpd_root_dir = httpd_root_dir[:httpd_root_dir.index("\n")]
                httpd_root_dir = httpd_root_dir.replace('"', '')

                if os.path.exists(httpd_root_dir) and os.path.isdir(httpd_root_dir):
                    server_config_file = os.path.join(httpd_root_dir, server_config_file)

            if os.path.exists(server_config_file):
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
