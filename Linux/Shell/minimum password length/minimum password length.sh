#!/bin/bash

pLen=$(cat /etc/login.defs | egrep "^PASS_MIN_LEN" | cut -f2)

if (( $pLen >= 14 )); then 
    echo "Password length is already set as per CIS guidelines"
else 
    sed -i 's/^PASS_MIN_LEN\t'$pLen'/PASS_MIN_LEN\t14/g' /etc/login.defs
    echo "Password Length change to 14 characters as per CIS recommendations"
fi