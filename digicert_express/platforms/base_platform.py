import os
import loggers

class BasePlatform():
    APACHE_SERVICE = 'apache2ctl'
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
