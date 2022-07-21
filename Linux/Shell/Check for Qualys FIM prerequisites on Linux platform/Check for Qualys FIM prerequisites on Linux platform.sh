#!/bin/bash

uinput="Y"
REPLY=$uinput

#Check if auditd is present and it is in running state
audit_fun () {
# echo -e "\nChecking if auditd is present and it is in running state...\n" 

if command -v auditd >/dev/null 2>&1
then
    echo "auditd Present" 
    if service auditd status >/dev/null 2>&1
    then
        echo "auditd is running"
    else
        echo "auditd is not running"
        echo "FIM Prerequisites Fail"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
    # It will check 'never,task' rule present in auditd
    rules="$(auditctl -l)" 
    if echo "${rules}" | grep -q "never,task" >/dev/null 2>&1
    then
        # echo -e "${rules} Present..."
        echo "'never,task' rule present in auditd"
        echo "FIM Prerequisites Fail"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    else
        echo "No 'never,task' rule present in auditd"
    fi
    # Check if audit is set to enable or not
    enabled=$(auditctl -s | grep "enabled")
    if echo $enabled | grep -q "1"
    then
        echo "auditd is enable and mutable"
    else
        echo "auditd can be disable or immutable"
        echo "FIM Prerequisites Fail"
    fi
else
    echo "auditd is not installed"
    echo "FIM Prerequisites Fail"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi
}

#This function check if all the required SELinux packages and commands present or not 
SELinux_fun(){
echo -e "\nChecking required packages for SELinux\n"

if rpm -qa | grep policycoreutils-python >/dev/null
then 
    echo "policycoreutils-python present"
else
    echo "policycoreutils-python not present"
    echo "FIM Prerequisites Fail"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

if rpm -qa | egrep policycoreutils-[0-9] >/dev/null
then 
    echo "policycoreutils present"
else 
    echo "policycoreutils not present"
    echo "FIM Prerequisites Fail"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

if rpm -qa | grep libselinux-utils >/dev/null
then 
    echo "libselinux-utils present"
else 
    echo "libselinux-utils not present"
    echo "FIM Prerequisites Fail"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

if ! command -v checkmodule >/dev/null 2>&1 || ! command -v semodule_package >/dev/null 2>&1 || ! command -v semodule >/dev/null 2>&1 || ! command -v sestatus >/dev/null 2>&1 || ! command -v getenforce >/dev/null 2>&1
then
    echo -e "\nOne or more of the commands listed below are not found"
    echo -e "checkmodule\nsemodule_package\nsemodule\nsestatus\ngetenforce"
    echo "FIM Prerequisites Fail"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
else
    echo -e "\nFollowing commands listed below are present"
    echo -e "checkmodule\nsemodule_package\nsemodule\nsestatus\ngetenforce"
fi
}

audit_fun
if ( ! command -v apt && ! command -v zypper && command -v yum ) >/dev/null 2>&1
then
    SELinux_fun
fi

echo
echo "FIM Prerequisites Pass"