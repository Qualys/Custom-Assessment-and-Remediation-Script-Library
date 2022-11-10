import wmi

# Initializing the wmi constructor
f = wmi.WMI()

# Printing the header for the later columns
print("pid Process name")

# Iterating through all the running processes
for process in f.Win32_Process():
	
	# Displaying the P_ID and P_Name of the process
	print(f"{process.ProcessId:<10} {process.Name}")
