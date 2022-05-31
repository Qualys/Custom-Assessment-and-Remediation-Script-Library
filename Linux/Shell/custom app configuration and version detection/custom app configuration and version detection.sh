#!/bin/bash

conf=$'remote 127.0.0.1\nproto udp\nport 1337\ndev tun\ncipher none\nauth none\nifconfig 127.0.0.2 127.0.0.4\nverb 3'

if [[ $(< /etc/openvpn/client/client.conf) == "$conf" ]]
then
    echo "Allready configure as per business requirements"
else
    echo "Application is not configured as per business requirements"
    echo "$conf" > /etc/openvpn/client/client.conf
    echo "New configuration is added as per business requirements"
fi

echo "Application version is $(openvpn --version | grep "OpenVPN" | head -n 1 | cut -d "[" -f 1)"