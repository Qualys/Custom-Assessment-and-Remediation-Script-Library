#!/bin/bash

pMaxDays=$(cat /etc/login.defs | egrep "^PASS_MAX_DAYS" | cut -f2)

if (( $pMaxDays <= 365 )); then 
    echo "Password Maximum Days is already set as per CIS guidelines"
else 
    sed -i 's/^PASS_MAX_DAYS\t'$pMaxDays'/PASS_MAX_DAYS\t60/g' /etc/login.defs
    echo "Password Maximum Days change to 60 Days as per CIS recommendations"
fi