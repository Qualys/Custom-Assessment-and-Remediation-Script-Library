#!/bin/bash

#User Need to change/add configuration in conf variable as per your requirement
conf=$'remote 127.0.0.1\nproto udp\nport 1337\ndev tun\ncipher none\nauth none\nifconfig 127.0.0.2 127.0.0.4\nverb 3'

#Change confLocation variable lactation to the configuration file location whose configuration needs to check
confLocation=/etc/openvpn/client/client.conf
if [[ $(< $confLocation) == "$conf" ]]
then
    echo "Allready configure as per business requirements"
else
    echo "Application is not configured as per business requirements"
    echo "$conf" > $confLocation
    echo "New configuration is added as per business requirements"
fi

#Change version variable if required 
version=$(openvpn --version | grep "OpenVPN" | head -n 1 | cut -d "[" -f 1)
echo "Application version is $version"