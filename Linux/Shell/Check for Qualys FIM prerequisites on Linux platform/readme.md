Check for Qualys FIM prerequisites on Linux platform  
  
This script will check for the following prerequisites  
1. Auditd is present and it is in running state  
2. Check and remove 'never,task' rule if present in auditd  
3. Check if all the required SELinux package and commands present or not  
      
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