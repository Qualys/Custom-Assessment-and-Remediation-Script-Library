#!/bin/bash

pam=$(cat /etc/ssh/sshd_config | grep ^UsePAM | awk -F" " '{printf $2}')

if [ $pam -eq "yes" ]; then 
    echo "SSH UsePAM is already set to yes as per CIS guidelines"
else 
    sed -i 's/^UsePAM '$pam'/UsePAM yes/g' /etc/ssh/sshd_config
    echo "SSH UsePAM is set to yes as per CIS recommendations"
fi