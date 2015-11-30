import loggers
import platform
import re

def normalize_common_name_file(common_name):
    return common_name.replace("*", "any").replace(".", "_")

def determine_platform():
    logger = loggers.get_logger(__name__)
    distro_name = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    logger.debug("Found platform: %s", " : ".join(distro_name))
    return distro_name

def create_regex(text):
    """
    Escape and return the passed string in upper and lower case to match regardless of case.
    Augeas 1.0 supports the standard regex /i but previous versions do not.  Also, not all (but most) unix/linux
    platforms support /i.  So this is the safest method to ensure matches.

    :param text: string to create regex from
    :return: regex
    """

    return "".join(["[" + c.upper() + c.lower() + "]" if c.isalpha() else c for c in re.escape(text)])
