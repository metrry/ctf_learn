a = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
for i in range(128):
    tmp = ""
    for j in "/bin/sh":
        aa =  ord(j) ^ i
        if aa in a:
            continue
        else:
            tmp+=chr(aa)

    if len(tmp) == 7:
        print tmp,hex(i)


