import config
import os

from base_platform import BasePlatform

class CentosPlatform(BasePlatform):
    APACHE_SERVICE = 'httpd'
    APACHE_PROCESS_NAME = 'httpd'
    APACHE_RESTART_COMMAND = 'service httpd restart'
    DEPS = ['openssl', 'augeas-libs', 'augeas', 'mod_ssl']

    def check_dependencies(self):
        try:
            self.logger.info("Checking for required dependencies")
            import yum
            yb = yum.YumBase()
            packages = yb.rpmdb.returnPackages()

            installed_packages = []
            ignored_packages = []
            for package_name in self.DEPS:
                if package_name in [x.name for x in packages]:
                    continue
                else:
                    if raw_input('Install: {0} (Y/n) '.format(package_name)).lower().strip() == 'n':
                        ignored_packages.append(package_name)
                        continue
                    else:
                        self.logger.info("Installing package {0}...".format(package_name))
                        os.system('yum -y install {0} &>> {1}'.format(package_name, config.LOG_FILE))
                        installed_packages.append(package_name)
                        continue
            if not installed_packages and not ignored_packages:
                self.logger.info("All dependencies are met.")
            return ignored_packages
        except ImportError:
            pass

    def include_ifmodule(self):
        return False

    def enable_ssl_mod(self):
        # TODO this should work
        return

    def _is_ssl_mod_enabled(self):
        # TODO this should work
        pass
