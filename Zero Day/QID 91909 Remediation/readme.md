Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability (CVE-2022-30190)    
  
Security researchers have discovered a new zero-day vulnerability in Microsoft Office, via Microsoft Support Diagnostic Tool (MSDT), that could be exploited to achieve code execution on affected systems simply by opening a malicious Word document.   
    
The vulnerability, tracked as CVE-2022-30190, was discovered by a Japanese security researcher nao_sec, who tweeted a warning about the zero-day over the weekend. Security researcher Kevin Beaumont named the vulnerability “Follina” because the spotted sample on the file references 0438, which is the area code of Follina in Italy.   
  
Workaround   
   
Microsoft has recommended disabling the MSDT URL protocol as a temporary fix. Disabling the MSDT URL protocol prevents troubleshooters from being launched as links, including links throughout the operating system. The following steps can be taken to disable the MSDT protocol.  
  
1. Run Command Prompt as Administrator.  
2. Back up the registry key and execute the command “reg export HKEY_CLASSES_ROOT\ms-msdt filename”  
3. Execute the command “reg delete HKEY_CLASSES_ROOT\ms-msdt /f”  
  
How to mitigate the risk until the vulnerability is remediated  
  
1. Workaround/Mitigation Detection  
Qualys Policy Compliance customers can evaluate workaround based on the following Control 24074 Status of the ‘Microsoft Support Diagnostic Tool (MSDT)’ service  
  
2. Executing workaround using Qualys CAR  
Qualys Custom Assessment and Remediation (CAR) customers can perform the provided mitigation steps by creating a PowerShell script and executing it on the vulnerable assets.