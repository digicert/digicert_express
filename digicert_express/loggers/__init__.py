import logging

class ExpressInstallLogger(object):
    def __init__(self, log_path=".", file_name="digicert_express.log"):
        logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
        self.log = logging.getLogger()

        consoleHandler = logging.StreamHandler()
        self.log.addHandler(consoleHandler)

        try:
            fileHandler = logging.FileHandler("{0}/{1}".format(log_path, file_name))
            fileHandler.setFormatter(logFormatter)
            self.log.addHandler(fileHandler)
        except IOError:
            pass

        self.log.setLevel(logging.DEBUG)

    def get_logger(self):
        return self.log
