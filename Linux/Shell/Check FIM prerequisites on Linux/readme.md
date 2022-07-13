Use this script to check for the following prerequisites:
  
1. Auditd is present and it is in running state  
2. Check for 'never,task' rule in auditd
3. Check if auditd is enable and mutable  
3. Check if all the required SELinux package and commands present 
      
-SELinux package  
    policycoreutils-python  
    policycoreutils  
    libselinux-utils  
      
-Commands  
    checkmodule  
    nsemodule_package  
    nsemodule  
    nsestatus  
    ngetenforce