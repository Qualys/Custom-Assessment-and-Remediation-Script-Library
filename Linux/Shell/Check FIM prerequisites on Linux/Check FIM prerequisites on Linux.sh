#!/bin/bash

read -p 'Want to start FIM prerequisite in non-interactive mode "y/n" ? ' -n 1 -r uinput
echo
if [[ ! $uinput =~ ^[Yy]$ ]]
then
    echo -e "\nStarting FIM prerequisite in interactive mode..."
else
    echo -e "\nStarting FIM prerequisite in non-interactive mode..."
    REPLY=$uinput
fi

#Check if auditd is present and it is in running state
audit_fun () {
echo -e "\nChecking if auditd is present and it is in running state...\n" 

if command -v auditd >/dev/null 2>&1
then
    echo "auditd Present" 
    if service auditd status >/dev/null 2>&1
    then
        echo "auditd is running"
    else
        [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to start auditd services "y/n" ?' -n 1 -r; echo; }
        if [[ $REPLY =~ ^[Yy]$ ]]
        then
            echo "starting audit..."
            service auditd start >/dev/null 2>&1
            if service auditd status >/dev/null 2>&1
            then
                echo "auditd is started and running"
            else
                echo "FIM Prerequisites fails"
                echo "Not able to start auditd"
                [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
            fi
        else
            echo "FIM Prerequisites fails"
            [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
    fi
else
    echo "audit is not installed"
    [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to install auditd services "y/n" ?' -n 1 -r ;echo; }
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        echo "Installing auditd"
        if command -v yum && ! command -v apt && ! command -v zypper >/dev/null 2>&1
        then
            yum install audit -y -q -e 0
        elif command -v apt >/dev/null 2>&1
        then
            apt install -y auditd >/dev/null 2>&1
        elif command -v zypper >/dev/null 2>&1
        then
            zypper install -y auditd >/dev/null 2>&1
        fi 
        if command -v auditd >/dev/null 2>&1
        then
            echo "starting audit..." 
            service auditd start >/dev/null 2>&1
            if service auditd status >/dev/null 2>&1
            then
                echo "auditd is started and running"
            else
                echo "FIM Prerequisites fails"
                echo "Not able to start auditd after installing"
                [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
            fi
        else
            echo "Not able to install auditd"
            echo "FIM Prerequisites fails"
            [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
    else
        echo "FIM Prerequisites fails"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
    
fi 
#It will remove 'never,task' rule present in auditd
rules="$(auditctl -l)" 
if echo "${rules}" | grep -q "never"
then
    echo "${rules} Present..."
    [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to remove "never,task" rule "y/n" ?' -n 1 -r;echo; }
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        echo "removing rule...." 
        auditctl -d never,task  
    else
        echo "FIM Prerequisites fails"
        echo "Not able to remove audit rule"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
fi 
 
}

#This function check if all the required SELinux packages and commands present or not 
SELinux_fun(){
echo -e "\nChecking required packages for SELinux\n"

if rpm -qa | grep policycoreutils-python >/dev/null
then 
    echo "policycoreutils-python present"
else 
    [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to install policycoreutils-python "y/n" ?' -n 1 -r;echo; }
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        yum install -y policycoreutils-python -q -e 0
        if rpm -qa | grep policycoreutils-python >/dev/null
        then
            echo "policycoreutils-python installed"
        else
            echo "not able to install policycoreutils-python packge"
            echo "FIM Prerequisites fails"
            [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
    else
        echo "FIM Prerequisites fails"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
fi

if rpm -qa | egrep policycoreutils-[0-9] >/dev/null
then 
    echo "policycoreutils present"
else 
    [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to install policycoreutils "y/n" ?' -n 1 -r;echo; }
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        yum install -y policycoreutils -q -e 0
        if rpm -qa | egrep policycoreutils-[0-9] >/dev/null
        then
            echo "policycoreutils installed"
        else
            echo "not able to install policycoreutils packge"
            echo "FIM Prerequisites fails"
            [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
    else
        echo "FIM Prerequisites fails"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
fi

if rpm -qa | grep libselinux-utils >/dev/null
then 
    echo "libselinux-utils present"
else 
    [[ $uinput =~ ^[Yy]$ ]] || { read -p 'Want to install libselinux-utils "y/n" ?' -n 1 -r;echo; }
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        yum install -y libselinux-utils -q -e 0
        if rpm -qa | grep libselinux-utils >/dev/null
        then
            echo "libselinux-utils installed"
        else
            echo "not able to install libselinux-utils packge"
            echo "FIM Prerequisites fails"
            [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
        fi
    else
        echo "FIM Prerequisites fails"
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
    fi
fi

if ! command -v checkmodule >/dev/null 2>&1 || ! command -v semodule_package >/dev/null 2>&1 || ! command -v semodule >/dev/null 2>&1 || ! command -v sestatus >/dev/null 2>&1 || ! command -v getenforce >/dev/null 2>&1
then
    echo "FIM Prerequisites fails"
    echo "One or more of the commands listed below are not found"
    echo -e "checkmodule\nsemodule_package\nsemodule\nsestatus\ngetenforce"
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

}

audit_fun
if ((! command -v apt && ! command -v zypper && command -v yum)) >/dev/null 2>&1
then
    SELinux_fun
fi

echo
echo "**********************"
echo "FIM Prerequisites PASS"
echo "**********************"