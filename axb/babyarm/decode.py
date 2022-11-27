

destring='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'
destr="Sp5jS6mpH6LZC6GqSWe="
for index in range(int(len(destr)/4)):
    index=4
    print(index)
    for i  in range(256):
        for j in range(256):
            for k in range(256):
                # print(i,j,k)
                tempstr=destring[int((i-i%4)/4)]
                tempstr+=destring[int((16*i)&0x30)|int(((j-j%16)/16))]
                if k:
                    tempstr+=destring[int((4*j)&0x3c)|int(((k-k%64)/64))]+destring[int(k&0x3f)]
                else:
                    tempstr+=destring[int((4*j)&0x3c)]+'='
        # print(tempstr)
                if tempstr==destr[index*4:index*4+4]:
                    print(chr(i)+chr(j)+chr(k))

#s1mpl3Dec0d4r
                