#!/bin/bash

aliveInterval=$(cat /etc/ssh/sshd_config | grep ClientAliveInterval | awk -F" " '{printf $2}')

if (( $aliveInterval >= 1 || $aliveInterval <= 900 )); then 
    echo "SSH Client Alive Interval is already as per CIS guidelines"
else 
    sed -i 's/^[#]ClientAliveInterval '$aliveInterval'/ClientAliveInterval 900/g' /etc/ssh/sshd_config
    echo "SSH Client Alive Interval is set to 900 as per CIS recommendations"
fi

aliveCountMax=$(cat /etc/ssh/sshd_config | grep ClientAliveCountMax | awk -F" " '{printf $2}')

if (( $aliveCountMax == 0 )); then 
    echo "SSH Client Alive Count Max is already as per CIS guidelines"
else 
    sed -i 's/^[#]ClientAliveCountMax '$aliveCountMax'/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
    echo "SSH Client Alive Count Max is set to 0 as per CIS recommendations"
fi