#!/bin/bash

pMinDays=$(cat /etc/login.defs | egrep "^PASS_MIN_DAYS" | cut -f2)

if (( $pMinDays >= 1 )); then 
    echo "Password Minimum Days is already set as per CIS guidelines"
else 
    sed -i 's/^PASS_MIN_DAYS\t'$pMinDays'/PASS_MIN_DAYS\t1/g' /etc/login.defs
    echo "Password Minimum Days change to 1 Day as per CIS recommendations"
fi