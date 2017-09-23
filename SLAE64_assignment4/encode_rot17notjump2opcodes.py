#!/usr/bin/python

# Python "Rot17-Not-Jump2Opcodes" encoder for shellcode
# Requires Python >= 2.6
# Read the shellcode from an external file including the text representation
# of the shellcode binary object 
# The input file could be prepared redirecting to a string file the output of the "get_shellcode.sh" script

import sys
import random

if (len(sys.argv) < 2):
    print 'Pass the object file as first parameter'
    print 'The input file should be an ASCII text file containing an hexadecimal lower case representation of the shellcode'
    print 'in the format \x00 f.i.: \xeb\x13\x5f'

    sys.exit()

try:
    with open((sys.argv[1]), "r") as shellcode:
        count = 0
        stringa = shellcode.read()
        code = []
        encoded_code = ''
        for i in range((len(stringa)/4)): # this is supposed to be used only on little endian systems and ascii files   
            if (( ord(stringa[i*4+2]) ) > 87): # (no unicode) 
                hbits = ord(stringa[i*4+2]) - 87
            else:
                hbits = ord(stringa[i*4+2]) - 48    
            if (( ord(stringa[i*4+3]) ) > 87): 
                lbits = ord(stringa[i*4+3]) - 87
            else:
                lbits = ord(stringa[i*4+3]) - 48      
            code.append(hbits*16+lbits) 

        for byte in code:
                    count+=3
                    tmp = (~((byte + 0x11) & 0xff)) & 0xff # This routine takes each original shell code bytes        
                    encoded_code += '0x{:02x},'.format(tmp)  # add 17, not the result and add to the final shellcode two random
                                                    # filler bytes different than 0. The increment value (0x11) has been choosen because
                                                    # the only opcode that would be encoded as 0x00 would be 0xEE (OUT) which I hardly believe
                                                    # would be useful in the context of shellcoding 
                    # encoded_code += '0x%02x,0x%02x,' %(random.randint(1,255))  %(random.randint(1,255)) 
                    encoded_code += '0x{:02x},0x{:02x},'.format(random.randint(1,255),  random.randint(1,255)) 
        encoded_code = encoded_code[:-1]
        print 'The resulting shellcode is the following:\n'
        print encoded_code
        print '\nLen of encoded code: %d' % count
except EnvironmentError:
    print 'Cannot open the file name: ', sys.argv[1]

finally:
    shellcode.close()
    


