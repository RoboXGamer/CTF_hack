Challenge Summary

The web application provides a simple interface that allows a user to ping an IP address. The description mentions that the service includes a WAF blocking dangerous shell characters, suggesting that command injection attempts may be filtered.

The objective is to retrieve the flag from the server.

1. Initial Reconnaissance

The interface contains a single input field:

Enter an IP address to ping

This strongly suggests the backend executes a command similar to:

ping <user_input>

A common insecure implementation for such tools is:

system("ping " + input)

or

/bin/sh -c "ping $input"

If user input is passed directly into a shell command, it creates a command injection vulnerability.

2. Testing for Command Injection

Typical command injection payloads include:

127.0.0.1;id
127.0.0.1 && id
127.0.0.1 | id

However, the challenge description states that a WAF blocks dangerous shell characters, so these payloads fail.

This suggests the filter blocks characters such as:

; & |

but may still miss other shell features.

3. Discovering Command Substitution

A useful alternative technique is command substitution using:

$(command)

If the backend runs the command through /bin/sh, the shell will execute the command inside $() and replace it with its output.

Test payload:

127.0.0.1$(id)

Server response:

ping: groups=0(root): Name or service not known

This response reveals that the id command executed successfully. The shell replaced $(id) with its output before passing it to ping.

Example expansion:

ping 127.0.0.1uid=0(root) gid=0(root) groups=0(root)

Ping then attempts to resolve each token as a hostname, producing error messages that leak the command output.

This confirms arbitrary command execution via $().

4. Searching for the Flag

Many CTF environments store the flag as:

a file (/flag, /flag.txt)
an environment variable (FLAG)

Enumerating environment variables can be done using:

127.0.0.1$(env)

The server response included environment variables such as:

CTF7_97A27E6B_SVC_PORT_5000_TCP_PROTO=tcp

Since environment variables are visible, the flag might also be stored there.

5. Extracting the Flag

To directly retrieve the flag variable:

127.0.0.1$(printenv FLAG)

If the flag is stored as:

FLAG=ctf7{example_flag}

the shell expands the command to:

ping 127.0.0.1ctf7{example_flag}

Ping then produces an error:

ping: 127.0.0.1ctf7{example_flag}: Name or service not known

The flag appears in the error message, revealing it to the attacker.

6. Root Cause of the Vulnerability

The vulnerability exists because user input is executed inside a shell command.

Example vulnerable code:

os.system("ping " + input)

Since a shell interprets the command, features like command substitution ($()) remain active even if certain characters are filtered.

7. Why the WAF Failed

The WAF likely filtered characters such as:

; &
|

However, it did not block $(), which is another method for executing commands inside the shell.

This allowed the attacker to bypass the filter and achieve command execution.

8. Secure Implementation

The correct approach is to avoid invoking the shell entirely.

Example secure implementation:

subprocess.run(["ping", input])

Passing arguments as a list ensures the command is executed directly without shell interpretation.

Additional protection should include:

strict IP validation
avoiding shell execution
escaping user input 9. Final Payload
127.0.0.1$(printenv FLAG)

This payload executes printenv FLAG, injects the result into the ping command, and leaks the flag through the ping error output.
