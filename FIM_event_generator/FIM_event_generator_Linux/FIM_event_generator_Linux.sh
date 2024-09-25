#!/bin/bash

# Removing Directory if already exist 
rm -rf /FIM_Test >/dev/null 2>&1

# Creating Temporary Directory for generating event   
mkdir /FIM_Test

FIM_Event_Generator()
{
    # Creating a File
    touch /FIM_Test/$1

    # Content Change 
    echo "File Content Change" > /FIM_Test/$1

    # Change File Permission 
    chmod 700 /FIM_Test/$1

    # Rename file 
    mv /FIM_Test/$1 /FIM_Test/New_$1

    # Remove File
    rm -rf /FIM_Test/New_$1
}

FIM_Event_Generator BASHLITE
FIM_Event_Generator CryptoLocker
FIM_Event_Generator EternalRocks
FIM_Event_Generator MEMZ
FIM_Event_Generator Regin
FIM_Event_Generator docu2.docx_rwuxrek
FIM_Event_Generator pict32.jpg_rwuxrek

# Change Directory Permission 
chmod -R 777 /FIM_Test

# Rename Directory 
mv /FIM_Test /FIM_Test_New

# Rename Directory 
mv /FIM_Test_New /FIM_Test 

# Change Directory Permission 
chmod -R 755 /FIM_Test

# Remove Directory
rm -rf /FIM_Test

echo ""
echo "FIM events generated"