# Crypt File (CUHK CSCI5470)

# Instruction
compile
```
gcc mycrypt.c -o mycrypt -lssl -lcrypto
```
encryption
```
./mycrypt -e -f file.pdf -lpri lpri.pem -spub spub.pem -lp 5470
```
decryption
```
./mycrypt -d -f file.pdf.enc -cert cert.pem -spri spri.pem -sp 0745
```
