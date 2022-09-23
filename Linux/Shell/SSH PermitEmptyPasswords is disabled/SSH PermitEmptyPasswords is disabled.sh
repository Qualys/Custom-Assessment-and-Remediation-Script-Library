#!/bin/bash

perm=$(cat /etc/ssh/sshd_config | grep PermitEmptyPasswords | awk -F" " '{printf $2}')

if [ $perm -eq "no" ]; then 
    echo "SSH empty password is prohibited as per CIS guidelines"
else 
    sed -i 's/^[#]PermitEmptyPasswords '$perm'/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
    echo "SSH empty password login is set to no as per CIS recommendations"
fi