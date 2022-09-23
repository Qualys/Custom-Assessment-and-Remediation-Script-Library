The PermitRootLogin parameter specifies if the root user can log in using ssh. The default is no.  

Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo. This in turn limits opportunity for nonrepudiation and provides a clear audit trail in the event of a security incident.  

This script will check if SSH root login is prohibited or not and if SSH root login is allowed then script will change it to not allow root login.  