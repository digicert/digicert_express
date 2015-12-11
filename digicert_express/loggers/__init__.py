import logging
import os

def get_logger(module_name, log_path='./'):
    root_logger = logging.getLogger()
    # Make sure the root logger doesn't already have handlers
    if not len(root_logger.handlers):
        # create console handler and set level to info
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        formatter = ExpressFormatter()
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

        # create debug file handler and set level to debug
        handler = logging.FileHandler(os.path.join(log_path, "ei_debug.log"), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    logger = logging.getLogger(module_name)
    logger.setLevel(logging.DEBUG)

    return logger

class ExpressFormatter(logging.Formatter):
    default_fmt = logging.Formatter('[%(levelname)s] %(name)s: %(message)s')
    info_fmt = logging.Formatter('%(message)s')

    def format(self, record):
        if record.levelno == logging.INFO:
            return self.info_fmt.format(record)
        else:
            return self.default_fmt.format(record)
