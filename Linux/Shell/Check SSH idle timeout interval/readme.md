The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions.  
    ClientAliveInterval sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The default is 0, indicating that these messages will not be sent to the client.  
    ClientAliveCountMax sets the number of client alive messages which may be sent without sshd receiving any messages back from the client. If this threshold is reached while client alive messages are being sent, sshd will disconnect the client, terminating the session. The default value is 3.   
        The client alive messages are sent through the encrypted channel  
        Setting ClientAliveCountMax to 0 disables connection termination  
  
Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value reduces this risk.  
    The recommended ClientAliveInterval setting is no greater than 900 seconds (15 minutes)  
    The recommended ClientAliveCountMax setting is 0  
    At the 15 minute interval, if the ssh session is inactive, the session will be terminated  