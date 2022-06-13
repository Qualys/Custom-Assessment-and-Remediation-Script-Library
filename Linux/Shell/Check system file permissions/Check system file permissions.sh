#!/bin/bash

# Ensure permissions on /etc/passwd are configured
echo "Set owner, group, and permissions on /etc/passwd"
chown root:root /etc/passwd
chmod u-x,g-wx,o-wx /etc/passwd

# Ensure permissions on /etc/passwd- are configured
echo "Set owner, group, and permissions on /etc/passwd-"
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

# Ensure permissions on /etc/shadow are configured
echo "Set owner, group, and permissions on /etc/shadow"
chown root:root /etc/shadow
chmod 0000 /etc/shadow

#  Ensure permissions on /etc/shadow- are configured
echo "Set owner, group, and permissions on /etc/shadow-"
chown root:root /etc/shadow-
chmod 0000 /etc/shadow-

# Ensure permissions on /etc/gshadow are configured
echo "Set owner, group, and permissions on /etc/gshadow"
chown root:root /etc/gshadow
chmod 0000 /etc/gshadow

# Ensure permissions on /etc/gshadow- are configured
echo "Set owner, group, and permissions on /etc/gshadow-"
chown root:root /etc/gshadow-
chmod 0000 /etc/gshadow-

# Ensure permissions on /etc/group are configured
echo "Set owner, group, and permissions on /etc/group"
chown root:root /etc/group
chmod u-x,g-wx,o-wx /etc/group

# Ensure permissions on /etc/group- are configured
echo "Set owner, group, and permissions on /etc/group-"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-


