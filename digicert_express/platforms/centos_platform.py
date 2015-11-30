from base_platform import BasePlatform

class CentosPlatform(BasePlatform):
    APACHE_SERVICE = 'httpd'
    DEPS = ['openssl', 'augeas-libs', 'augeas', 'mod_ssl']
