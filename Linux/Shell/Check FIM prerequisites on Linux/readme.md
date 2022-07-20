Use this script to check for the following prerequisites:  
  
1. auditd is present and in running state   
2. 'never,task' rule does not exist in the audit subsystem  
3. auditd is in non-immutable state  
4. Following packages and commands are present in case SELinux is enabled in enforcing or permissive mode  
SELinux package  
    policycoreutils-python  
    policycoreutils  
    libselinux-utils  
-Commands    
    checkmodule  
    semodule_package  
    semodule  
    sestatus  
    getenforce
