# Executing YARA rules on LINUX using Qualys CAR  

Qualys CAR can be leveraged to execute YARA rules on LINUX assets. The user needs to perform the following steps to run YARA rules via SHELL:

### Step 1
Encode the contents of the YARA rules file with base 64 encoding. You can use https://www.base64encode.org/

### Step 2
Create a shell script with the encoded YARA rules as follows:

```shell-script
#!/bin/bash
 
yaraRule="<base64encoded text>"
echo $yaraRule | base64 -d > /tmp/tmpYara
yara -s -r /tmp/tmpYara <path to scan>
```

### Step 3
Add this SHELL script on Qualys CAR and execute it on the required assets.