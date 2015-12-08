from base_platform import BasePlatform

class UbuntuPlatform(BasePlatform):
	APACHE_SERVICE = 'apache2ctl'
	APACHE_RESTART_COMMAND = 'service apache2 restart'
