This challenge revolves around a C program that encrypts the file containing a flag based on changing keys, and a core dump that contains said keys. We have `encyrypted_flag.bin`, we just have to find a way to decrypt the flag. 

First of all, we are given the binary `otp` and its source code, `otp.c`:

<details>
  <Summary><i><ins>Click to expand otp.c</ins></i></Summary>
<div markdown=1>

```c
  
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define KEYS 1000

int RANDOM_FD = -1;

void dump() {
    char cmd[128];
    int pid = getpid();
    snprintf(cmd, sizeof(cmd), "gcore -o dump %d; mv dump.%d dump", pid, pid);
    system(cmd);
}

void otp(unsigned char* p, int n, int depth) {
    char key[128];

    read(RANDOM_FD, key, n);
    for (int i = 0; i < n; ++i) {
        p[i] ^= key[i];
    }

    if (depth < KEYS - 1) {
        otp(p, n, depth + 1);
    } else {
        dump();
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <FLAG_FILE> <ENCRYPTED_FLAG_FILE>\n", argv[0]);
        return 0;
    }
    char* flag = argv[1];
    char* encrypted_flag = argv[2];
    RANDOM_FD = open("/dev/urandom", O_RDONLY);
    unsigned char p[128];

    int fd = open(flag, O_RDONLY);
    if (fd < 0) {
        printf("%s not found\n", flag);
        return 0;
    }
    int n = read(fd, p, 128);
    int write_fd = open(encrypted_flag, O_WRONLY | O_CREAT, 0644);
    if (n > 1) {
        if (p[n - 1] == '\n') {
            --n;
        }
        otp(p, n, 0);
        write(write_fd, p, n);
    }
    close(RANDOM_FD);
    close(fd);
    close(write_fd);
}
```
</div>
</details>

As we can see, it seems to generate random keys by using `/dev/urandom` and encrypts our flag by XOR'ing the bytes of the flag by the bytes of the key. This is done over and over again. Well, how do we get those keys? This is where the core dump comes into play.

We can run the `otp` binary with the core dump in order to examine the registers and the program execution from the dump. 

We can do this pretty easily with `gdb <path to binary> <path to dump>`

![image](https://github.com/user-attachments/assets/be53cfea-d4b3-4827-893c-e7f0350859b3)

Alright, so how do we get the keys?

Well, we can run `bt` to see all the function calls at the time of the crash. 

![image](https://github.com/user-attachments/assets/57541dd4-a554-4306-be3b-d379f433b4a1)

Alright, so we can see a whole lot of frames, 1003 in fact, and most of the function calls are calling `otp()`, which as we saw from the source code, is what's used to "encrypt" (it's just XOR'ing) the flag. 

If we scroll all the way back, we see that `otp()` is called for the first time during frame 4

![image](https://github.com/user-attachments/assets/99fad67c-fadd-4233-ae66-af6ae0a6f5b3)

So from frames 4-1003, new random keys are being generated and are being XOR'd with our flag. Thankfully, XOR is reversible, so we can reverse this process, but we need all those keys. 

Well, we can use `frame <frame number>` to switch to a stack frame and inspect registers and variables on the stack. I switch to the most recent stack frame, which is frame 1003

![image](https://github.com/user-attachments/assets/f987d6df-d142-4c87-bd68-befd638f3f2c)

Well, from the source code, we see that the name of key variable is straight up just `key`. Let's try running `x/128bx key` to see if we get anything? We're trying to print 128 bytes of hex at the `key` variable. We do 128 bytes since in the source code, we see that the
char array variable is initalized with `char key[128]`

We get:

![image](https://github.com/user-attachments/assets/cdd54273-4f7e-43dc-b7e4-825d40d2cb8e)

Alright nice the key got printed for this stack frame!

Something interesting though is all those 0's in the middle. Perhaps the key doesn't take up the entire 128 bytes? It looks like the key probably ends at `0xf6`, which is the 59th byte. We'll keep that in mind for now

![image](https://github.com/user-attachments/assets/012699f8-4b72-45c8-8395-ea92ee3e93b7)

Let's try the next stack frame, frame 1002

![image](https://github.com/user-attachments/assets/6707bed7-df5f-44d2-abbe-2c933c048a64)

If we run `x/128bx key` again, we get

![image](https://github.com/user-attachments/assets/5760417a-b5f4-400e-a53a-71d8f8294f25)

Again, everything after the 59th byte seems to be mostly zero! It seems that our key is actually 59 bytes, and not 128. 

Now that we have a pretty good grasp of what's going on, we just need to go through each stack frame starting from 1003 and going all the way back to 4 to get the keys, and XOR that with our encrypted flag. Instead of doing, `x/128bx key`, we'll instead do
`x/59bx key` since we know the key is only 59 bytes long. We can automate getting those keys with a gdb script, like so:

<details>
  <Summary><i><ins>Click to expand extract_keys.gdb</ins></i></Summary>
<div markdown=1>
  
```
  # extract_keys.gdb

# Set the frame number you want to start from
set $frame = 1003

# Loop through frames and retrieve key, stop when frame reaches 4
while $frame >= 4
    # Print the key for the current frame
    printf "Frame %d:\n", $frame
    
    # Go to the current frame
    frame $frame

    # Get the key at the address of 'key' (59 bytes)
    x/59xb &key 
    
    # Decrement the frame number
    set $frame = $frame - 1
end
```
</div>
</details>

We can run this and save the output to another file with `gdb -batch -x <path to gdb script> <path to binary> <path to dump> >> <file to save output>`

I'll send the output to a file named `extracted_keys.txt`

Running `gdb -batch -x extract_keys.gdb otp dump >> extracted_keys.txt` gets us this very long file (this is just some of the output)

<details>
  <Summary><i><ins>Click to expand extracted_keys.txt</ins></i></Summary>
  <div markdown=1>
    
  ```
  Frame 10:
#10 0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e1) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a1840:	0x31	0xcf	0x0d	0x15	0xff	0xe0	0x28	0x54
0x7ffe603a1848:	0x87	0x26	0x40	0x3b	0x86	0x6f	0xc2	0xf3
0x7ffe603a1850:	0x81	0x2c	0xac	0x1d	0xbe	0x96	0x5c	0x6f
0x7ffe603a1858:	0xf0	0x81	0x7e	0x7e	0xe2	0x76	0x7e	0x2c
0x7ffe603a1860:	0x35	0xed	0x01	0x47	0x65	0x65	0x38	0x1c
0x7ffe603a1868:	0xeb	0x91	0x17	0x3c	0x41	0xe3	0x67	0xc4
0x7ffe603a1870:	0x84	0xf5	0x9d	0x78	0x72	0xe1	0x42	0xec
0x7ffe603a1878:	0x9d	0xe1	0x01
Frame 9:
#9  0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e2) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a1780:	0xc2	0x84	0xbb	0x4f	0x69	0xaa	0x1f	0xb0
0x7ffe603a1788:	0xa9	0x9c	0x1f	0x9c	0xc6	0x61	0xa3	0x9a
0x7ffe603a1790:	0x8a	0x11	0x79	0x10	0x96	0x0b	0xb8	0x82
0x7ffe603a1798:	0xd1	0xd5	0xa2	0x2b	0x05	0x01	0x6b	0x3a
0x7ffe603a17a0:	0xfe	0xbe	0x4a	0x1c	0xb8	0x38	0xb3	0x6b
0x7ffe603a17a8:	0x16	0x89	0x5e	0xbb	0x94	0x63	0x1c	0x9d
0x7ffe603a17b0:	0x62	0xfb	0x47	0xa4	0x70	0x35	0x52	0x16
0x7ffe603a17b8:	0xfb	0x6b	0xbf
Frame 8:
#8  0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e3) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a16c0:	0x0e	0x25	0xaa	0x33	0x5c	0x78	0xeb	0x10
0x7ffe603a16c8:	0x3b	0xf3	0x76	0x56	0x4a	0x5c	0xde	0x80
0x7ffe603a16d0:	0x18	0xfc	0x1a	0x6a	0x3f	0xd5	0x53	0x52
0x7ffe603a16d8:	0x22	0x50	0x62	0xf6	0x83	0x47	0xb7	0x04
0x7ffe603a16e0:	0xdb	0xee	0x86	0x7b	0x6a	0x07	0x63	0x71
0x7ffe603a16e8:	0xae	0x64	0x04	0xf6	0xa3	0x0b	0x18	0xff
0x7ffe603a16f0:	0x94	0xbd	0x98	0xc5	0x5d	0xb6	0x0f	0xb3
0x7ffe603a16f8:	0x2d	0x28	0xa5
Frame 7:
#7  0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e4) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a1600:	0xa5	0x4e	0xee	0x13	0x11	0x9f	0x29	0x67
0x7ffe603a1608:	0xa1	0xa1	0x2b	0x35	0x43	0x70	0xf6	0x56
0x7ffe603a1610:	0x9a	0x33	0xfa	0xdb	0x2e	0x91	0x4f	0x0e
0x7ffe603a1618:	0x67	0xd9	0x6b	0x2d	0x4a	0x3c	0x0b	0xc3
0x7ffe603a1620:	0x16	0x07	0x9d	0x24	0xf6	0xe9	0xb0	0x8a
0x7ffe603a1628:	0x24	0xee	0x66	0x72	0x35	0xd0	0x7f	0xaf
0x7ffe603a1630:	0x1a	0x72	0xd8	0x75	0x38	0x7c	0x01	0x6d
0x7ffe603a1638:	0x27	0x5c	0xd2
Frame 6:
#6  0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e5) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a1540:	0x3c	0x11	0x86	0xe1	0x7d	0xd0	0xd5	0xc9
0x7ffe603a1548:	0xbb	0xdd	0x44	0x34	0xab	0x90	0x46	0xbc
0x7ffe603a1550:	0xe7	0xe8	0xfc	0x2f	0xe1	0x2c	0x6d	0xd4
0x7ffe603a1558:	0x71	0xc8	0x50	0x9e	0xc4	0x7b	0xce	0xca
0x7ffe603a1560:	0x7d	0x28	0xe3	0x1c	0x99	0xff	0xc7	0x13
0x7ffe603a1568:	0x71	0x99	0x8f	0xa7	0xd9	0x63	0x51	0xa5
0x7ffe603a1570:	0x0e	0xf2	0xcb	0x6c	0xc1	0xc1	0x93	0x41
0x7ffe603a1578:	0x3b	0x73	0x26
Frame 5:
#5  0x00000000004012a6 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e6) at /otp.c:27
27	        otp(p, n, depth + 1);
0x7ffe603a1480:	0x16	0x1b	0xbc	0x54	0x76	0xb4	0xe8	0xe9
0x7ffe603a1488:	0x49	0x7b	0x2d	0xa7	0x40	0xc3	0x4f	0x81
0x7ffe603a1490:	0x9c	0x6a	0x45	0xe8	0x66	0x94	0x06	0x61
0x7ffe603a1498:	0xc2	0xc7	0xcf	0xe4	0xba	0xa4	0x56	0xb8
0x7ffe603a14a0:	0xcf	0xae	0x20	0x25	0xaa	0x54	0x65	0x87
0x7ffe603a14a8:	0xc6	0x19	0xee	0x30	0xeb	0x8c	0x55	0xd7
0x7ffe603a14b0:	0xa3	0x68	0xa5	0xca	0x20	0x7f	0x16	0x52
0x7ffe603a14b8:	0xfa	0x37	0xdc
Frame 4:
#4  0x00000000004012b2 in otp (p=0x7ffe603d01d0 "\203U\263k\221\221\031\017\206\bz\350$q\240v\352wN\037\236\253\371\024\200\335LT\264/\232\001!S\271r\221\r1\303\020\277\246Kr(\225'p1\333N\005\334\353\327r\357\177\n\376\177", n=0x3b, depth=0x3e7) at /otp.c:29
29	        dump();
0x7ffe603a13c0:	0x38	0x09	0x88	0xb7	0x33	0xe9	0x5c	0x1c
0x7ffe603a13c8:	0x34	0x01	0xb7	0x8a	0xff	0x7b	0x61	0xb4
0x7ffe603a13d0:	0xc7	0xbe	0x5e	0xf7	0x9c	0x3c	0xd7	0x77
0x7ffe603a13d8:	0x44	0xf4	0x00	0x44	0x03	0x14	0xf1	0x60
0x7ffe603a13e0:	0xf4	0x85	0x2f	0x05	0x5d	0x6a	0xf8	0x7d
0x7ffe603a13e8:	0x87	0xeb	0x24	0x1d	0x08	0x7c	0xa0	0xa8
0x7ffe603a13f0:	0x47	0xf9	0xd8	0x20	0x19	0x8b	0x7e	0x5a
0x7ffe603a13f8:	0x08	0xf5	0x2d
```
</div>
</details>

This file is extremely long so no way are we parsing this by hand. From the output, we can see that the key bytes for each stack frame follow a line that begins with `0x<some big hex value>:`

We can write a Python script to parse this output file, get the key from each stack frame, XOR it with our encrypted flag in `encrypted_flag.bin`, and print the output

<details>
  <Summary><i><ins>Click to expand otp_solve.py</ins></i></Summary>
  <div markdown=1>
    
```python
# Open the encrypted_flag.bin file in binary mode
with open('encrypted_flag.bin', 'rb') as file:
    encrypted_flag = file.read()

# Print the bytes in a readable format (e.g., a list of hexadecimal values)
print("Encrypted Flag (in hex):")
encrypted_flag = list(encrypted_flag)  # Convert byte data to a list of integers
print(encrypted_flag)


keys = []

current_key = []
# Open the output log file
with open('extracted_keys.txt', 'r') as f:
    for line in f:
  
        if line[0:2] == "0x":
            #print(line)
            begin = line.index(":")
            #print(line[begin+1:].split("\t"))
            key_arr = line[begin+1:].split("\t")
            key_arr = [hex.strip().replace("\n", "") for hex in key_arr]

            for hex in key_arr:
                if hex != "":
                    current_key.append(int(hex, 16))
                if(len(current_key) == 59):
                    keys.append(current_key)
                    current_key = []
                    break
            #print(key_arr)


decrypted_flag = []

for key in keys:
    for i in range(len(encrypted_flag)):
        encrypted_flag[i] ^= key[i]

print("Final")
print(encrypted_flag)

printable_string = ''.join([chr(byte) for byte in encrypted_flag])

# Print the result
print(printable_string)
```
  </div>
</details>

Running this gets us:

![image](https://github.com/user-attachments/assets/4202d074-c17f-4cad-ab45-85406d5458b1)

The flag is `gigem{if_you_did_that_manually_i_am_so_sorry_for_your_loss}`

This challenge is complete!
