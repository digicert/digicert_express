#!/bin/bash

LOG_FILE="digicert_express_install.log"
# DYNAMIC STUFF
# order details
DOMAIN="example.digicert.com"
DOMAIN_PATH=`echo "$DOMAIN" | sed -e "s/\./_/g" | sed -e "s/*/any/g"`
FILEPATH="/etc/digicert/$DOMAIN_PATH"
ORDER="814496"
SUB=""
ALLOWDUPS=""

CERTIFICATE=""


CERTIFICATE_CHAIN=""

function dc_log {
    echo $1 | tee -a ${LOG_FILE}
}

function cent_is_package_installed {
    if yum list installed "$@" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

dc_log
dc_log "DigiCert Express Install Bootstrapper"
dc_log

CHECK_INSTALL_PACKAGES=""
DIGICERT_PYTHON_PACKAGES="digicert-client digicert-express"
CHECK_PYTHON_PACKAGES="python-augeas requests ndg-httpsclient pyasn1"
touch ${LOG_FILE}
start_date=`date`
dc_log "${start_date}"

# ask for agreement to T&C
read -p "I agree to the terms & conditions at: https://www.digicert.com/docs/agreements/DigiCert_SA.pdf [y/N] " REPLY
if ! [[ "$REPLY" = "y" || "$REPLY" = "Y" || "$REPLY" = "Yes" || "$REPLY" = "yes" || "$REPLY" = "YES" ]]; then
    dc_log "You must accept the terms & conditions to use this program"
    exit
fi


# check for distribution, debian, centos, ubuntu
if [ -f /etc/lsb-release ]
then
        os=$(lsb_release -s -d)
elif [ -f /etc/debian_version ]; then
        os="Debian $(cat /etc/debian_version)"
elif [ -f /etc/centos-release ]; then
        os=`cat /etc/centos-release`
elif [ -f /etc/redhat-release ]; then
        os=`cat /etc/redhat-release`
else
        os="$(uname -s) $(uname -r)"
fi
echo "Found OS: ${os}"

# check for OS, Version, and Apache Version compatibility
# TODO this needs to be made more clear so users know what they did wrong

INSTALL_PACKAGES=""
PY_VERSION=`python -c 'import sys; print "%s.%s" % (sys.version_info[0], sys.version_info[1])'`
PYVARRAY=(${PY_VERSION//./ })
if [[ $os == *"CentOS"* ]]
then
    APACHE_VERSION=`apachectl -v | grep 'Server version' | cut -d '/' -f 2 | cut -d ' ' -f 1`
    if [[ ! $os =~ "6.5" ]] || [ ${PYVARRAY[0]} -lt 2 ] || [ ${PYVARRAY[1]} -lt 6 ] || [[ ! $APACHE_VERSION =~ "2.2" ]]; then
        echo ""
        echo "The requirements to run DigiCert Express Install are Cent OS 6.5 with Python 2.6.x and Apache 2.2.x"
        echo ""
        exit
    fi

    # Check to see if pip is installed just in case.
    pip -V >> /dev/null 2>&1
    if [ $? -eq 127 ]
    then
        # If pip is not installed, check to see if we can use wget to install it.
        wget --version >> /dev/null 2>&1
        if [ $? -ne 0 ]
        then
            dc_log "wget is not installed.  Please install wget by typing: 'sudo yum install wget'"
            exit
        else
            dc_log "Installing Python PIP package using wget method"
            wget --no-check-certificate --directory-prefix=/tmp https://bootstrap.pypa.io/get-pip.py >> ${LOG_FILE} 2>&1
            sudo python /tmp/get-pip.py >> ${LOG_FILE} 2>&1
        fi
    fi

    PACKAGES="augeas openssl augeas-libs mod_ssl pyOpenSSL"
    for package in $PACKAGES; do
        if ! cent_is_package_installed $package; then
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="yum"
        fi
    done

    if [ ${PYVARRAY[1]} -le 6 ]; then
        CHECK_PYTHON_PACKAGES="$CHECK_PYTHON_PACKAGES argparse"
    fi

    SYMLINK_PATH="/usr/sbin/express_install"
else
    APACHE_VERSION=`apachectl -v | grep 'Server version' | cut -d '/' -f 2 | cut -d ' ' -f 1`
    if [[ ! $os =~ "14.04" ]] || [ ${PYVARRAY[0]} -lt 2 ] || [ ${PYVARRAY[1]} -lt 7 ] || [[ ! $APACHE_VERSION =~ "2.4" ]]; then
        echo ""
        echo "The requirements to run DigiCert Express Install are Ubuntu 14.04 with Python 2.7.x and Apache 2.4.x"
        echo ""
        exit
    fi

    if [ "dpkg-query -W python-pip | awk {'print $1'} = """ ]; then
        dc_log "Updating APT repo and installing Python PIP package"
        sudo apt-get update >> ${LOG_FILE} 2>&1
        sudo apt-get install -q -y python-pip >> ${LOG_FILE} 2>&1
    fi

    # check for architecture 32 bit or 64 bit
    MACHINE_TYPE=`uname -m`
    if [ ${MACHINE_TYPE} = "x86_64" ]; then
        CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools libaugeas0 openssl python-openssl"
    else
        CHECK_INSTALL_PACKAGES="augeas-lenses augeas-tools:i386 libaugeas0:i386 openssl python-openssl"
    fi

    for package in $CHECK_INSTALL_PACKAGES; do
        if dpkg --get-selections | grep -q "^$package[[:space:]]*install$" >> ${LOG_FILE}; then
            dc_log "Prerequisite package $package is already installed."
        else
            INSTALL_PACKAGES="$INSTALL_PACKAGES $package"
            install_cmd="apt-get"
        fi
    done

    SYMLINK_DIR="/usr/local/bin/express_install"
fi

# check for python dependency modules
PYTHON_PACKAGES=""
for package in $CHECK_PYTHON_PACKAGES; do
    installed_package=`pip list | grep $package | cut -c -${#package}`
    if [ "$installed_package" = "$package" ]; then
        dc_log "Prerequisite Python package $package is already installed."
    else
        PYTHON_PACKAGES="$PYTHON_PACKAGES $package"
    fi
done

# TODO this needs to rely more on the version of the packages being installed. What if they need to be upgraded?
MISSING_DIGICERT_PYTHON_PACKAGES=""
for package in $DIGICERT_PYTHON_PACKAGES; do
    installed_package=`pip list | grep $package | cut -c -${#package}`
    if [ "$installed_package" = "$package" ]; then
        dc_log "Prerequisite Python package $package is already installed."
    else
        MISSING_DIGICERT_PYTHON_PACKAGES="$MISSING_DIGICERT_PYTHON_PACKAGES $package"
    fi
done

# Tell the user what we need to install
if ! [ "$INSTALL_PACKAGES" = "" ]; then
    dc_log "The following system packages need to be installed: $INSTALL_PACKAGES"
fi
if ! [ "$PYTHON_PACKAGES" = "" ]; then
    dc_log "The following Python packages need to be installed: $PYTHON_PACKAGES"
fi
if ! [ "$MISSING_DIGICERT_PYTHON_PACKAGES" = "" ]; then
    dc_log "The following DigiCert packages need to be installed: $MISSING_DIGICERT_PYTHON_PACKAGES"
fi


# install the dependencies
if ! [[ "$INSTALL_PACKAGES" = "" && "$PYTHON_PACKAGES" = "" && $MISSING_DIGICERT_PYTHON_PACKAGES = "" ]]; then
    read -p "Do you wish to install these packages? [Y/n] " REPLY
    if ! [ "$REPLY" = "n" ]; then
        if ! [ "$INSTALL_PACKAGES" = "" ]; then
            dc_log "Installing system packages. Please wait."
            sudo $install_cmd -q -y install $INSTALL_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        if ! [ "$PYTHON_PACKAGES" = "" ]; then
            dc_log "Installing Python packages. Please wait."
            sudo pip install $PYTHON_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        if ! [ "$MISSING_DIGICERT_PYTHON_PACKAGES" = "" ]; then
            dc_log "Installing DigiCert packages. Please wait."
            sudo pip install --pre $MISSING_DIGICERT_PYTHON_PACKAGES >> ${LOG_FILE} 2>&1
            if [ $? -ne 0 ]; then
                dc_log "Installation of package $package failed - aborting."
                exit
            fi
        fi
        dc_log "All prerequisite packages have been installed."
    else
        dc_log "Prerequisite packages are required in order to continue."
        exit
    fi
fi

# create a link so we can be run from the CLI
LINK_PATH="`pip show digicert-express | grep Location | cut -d ':' -f 2 | tr -d '[[:space:]]'`/digicert_express/express_install.py"
if [ -e "$LINK_PATH" ]; then
    dc_log "Adding links to run DigiCert Express Install in ${LINK_DIR}"
    sudo ln -s "$LINK_PATH" "$SYMLINK_PATH"
    sudo chmod 755 "$LINK_PATH"
    dc_log ""
    dc_log "DigiCert Express Install has been installed on your system."
    dc_log "As root, run 'express_install all' to install your certificate,"
    dc_log "or 'express_install --help' for more information."
    dc_log ""
fi

# Check for a bundled certificate, if one exists save it to a file in a defined path
CERT_PATH=""
if ! [[ "$DOMAIN" = "" || "$ORDER" = "" ]]; then
    if ! [[ "$CERTIFICATE" = "" || "$CERTIFICATE_CHAIN" = "" ]]; then
        sudo mkdir -p "$FILEPATH"
        CERT_NAME=`echo "$DOMAIN" | sed -e "s/\./_/g" | sed -e "s/*/any/g"`

        # write the certificate to file
        CERT_PATH="$FILEPATH/$CERT_NAME.crt"
        dc_log "Copying certificate file to $CERT_PATH"
        echo "$CERTIFICATE" | sudo tee "$CERT_PATH" > /dev/null

        dc_log "Copying certificate chain file to $FILEPATH/DigiCertCA.crt"
        echo "$CERTIFICATE_CHAIN" | sudo tee "$FILEPATH/DigiCertCA.crt" > /dev/null
    fi

    # run express install
    dc_log "running: sudo express_install --cert_path \"$CERT_PATH\" --order_id \"$ORDER\" --sub_id \"$SUB\" --allow_dups \"$ALLOWDUPS\""
    sudo express_install --cert_path "$CERT_PATH" --order_id "$ORDER" --sub_id "$SUB" --allow_dups "$ALLOWDUPS"

else
    dc_log "ERROR: You are missing your domain name or order id, please contact digicert support"
fi

dc_log ""
dc_log "DigiCert Express Install Finished"
end_date=`date`
dc_log "${end_date}"
