#!/bin/bash

pWarnAge=$(cat /etc/login.defs | egrep "^PASS_WARN_AGE" | cut -f2)

if (( $pWarnAge >= 7 )); then 
    echo "Password Warring Age is already set as per CIS guidelines"
else 
    sed -i 's/^PASS_WARN_AGE\t'$pWarnAge'/PASS_WARN_AGE\t7/g' /etc/login.defs
    echo "Password Warring Age change to 7 Days as per CIS recommendations"
fi