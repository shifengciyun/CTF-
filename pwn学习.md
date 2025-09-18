# Pwn 

## 汇编语言
>一个指令，一个或两个操作数

两个操作数时：一个目标操作数，一个原操作数 eg:mov  rbp,rsp   将rsp的值赋值到rbp上
                                           movq %rsp,%rbp  rbp=rsp
add表示加，sub表示减 xor异或 call调用函数 ，movzx将后面赋值到前
lea：Load effective address lea rax，[rbp-0x18]   #rax=[rbp-0x18]
xor: xor ebx,ebx  #使ebx=0，有影响标志寄存器的副作用，mov没有 
cmp:al,0x61 #al-0x61
sub:al,0x61 #al=al-0x61


0-255
8       16     32     64
BYTE    WORD   DWORD  QWORD


