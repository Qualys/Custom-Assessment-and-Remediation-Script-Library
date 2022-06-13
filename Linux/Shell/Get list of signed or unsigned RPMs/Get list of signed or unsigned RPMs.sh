#!/bin/bash
#Check if the system is base on RHEL
if ((! command -v apt && ! command -v zypper && command -v yum)) >/dev/null 2>&1
then
    echo -e "$(tput setaf 2)List of signed RPMs Installed on the system$(tput sgr0)\n"
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig} %{SIGGPG:pgpsig}\n' | grep -v "(none) (none)"

    echo -e "\n------------------------------------------------------------------------------------------------------------------\n"
    echo -e "$(tput setaf 1)List of Unsigned RPMs Installed on the system$(tput sgr0)\n"
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig} %{SIGGPG:pgpsig}\n' | grep "(none) (none)" | grep -v "gpg-pubkey"
else
    echo "This machine is not base on Red Hat"
fi