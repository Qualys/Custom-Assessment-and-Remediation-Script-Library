#(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
net accounts /lockoutduration:30

#(L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
net accounts /lockoutthreshold:30

#(L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
net accounts /lockoutwindow:30

#(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
net accounts /UNIQUEPW:24

#(L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
net accounts /MAXPWAGE:90

#(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
net accounts /MINPWAGE:30

# (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
net accounts /MINPWLEN:14