#!/bin/bash
# I'm not the author of the script. All the credits goes to user "arno" of commandlinefu.com
# http://www.commandlinefu.com/commands/view/12151/get-shellcode-of-the-binary-using-objdump
for i in $(objdump -d $1 -M intel | grep "^ " |cut -f2); 
do echo -n '\x'$i; 
done; 
echo
	
