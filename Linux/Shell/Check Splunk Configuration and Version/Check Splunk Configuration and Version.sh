#!/bin/bash

#Organization Splunk Server Configuration
conf="[general]
serverName = fimdemo3
pass4SymmKey = $7$ydFLF38oNC7F816+5u24Mylyuc9feUCBSAa8i0KgDeVgE2hOu/gFmg==

[sslConfig]
sslPassword = $7$lEml/HskhFx1bLIxf4HsIvXUKTCQ6aeU4PorZJ3YBSvUfpPG8kLSSw==

[lmpool:auto_generated_pool_download-trial]
description = auto_generated_pool_download-trial
quota = MAX
slaves = *
stack_id = download-trial

[lmpool:auto_generated_pool_forwarder]
description = auto_generated_pool_forwarder
quota = MAX
slaves = *
stack_id = forwarder

[lmpool:auto_generated_pool_free]
description = auto_generated_pool_free
quota = MAX
slaves = *
stack_id = free

[httpServer]
disableDefaultPort = true"


if [[ $(< /opt/splunk/etc/system/local/server.conf) == "$conf" ]]
then
echo "Accurate Configuration"
else
echo "Inaccurate Configuration"
echo "$conf" > /opt/splunk/etc/system/local/server.conf
echo "Configuration updated as per organization's hardening guidelines"
fi

echo "Splunk Version:$(cat /opt/splunk/etc/splunk.version)"