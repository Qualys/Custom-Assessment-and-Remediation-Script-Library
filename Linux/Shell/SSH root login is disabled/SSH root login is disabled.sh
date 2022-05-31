#!/bin/bash

perm=$(cat /etc/ssh/sshd_config | grep ^PermitRootLogin | awk -F" " '{printf $2}')

if [ $perm -eq "no" ]; then 
    echo "SSH root login permission is already set as per CIS guidelines"
else 
    sed -i 's/^PermitRootLogin '$perm'/PermitRootLogin no/g' /etc/ssh/sshd_config
    echo "SSH root login permission is set to no as per CIS recommendations"
fi