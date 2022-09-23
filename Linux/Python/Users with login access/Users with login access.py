#Import the OS module
import os

#The shell command to run
command = "getent shadow | egrep '^[^:]*:[*!]:' -v | cut -f1 -d:"

try:

#Runs the system command
    result = os.system(command)

#Prints the result of the command
    print(result)

#Prints an error message, in case an error occurs
except:
    print("An error occurred")