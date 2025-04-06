This one was a fun Minecraft related rev challenge. 

We are told that the user's Spigot Minecraft server files have been encrypted. Extracting the archive `.tar.gz` file they give us, let's take a look at the server

![image](https://github.com/user-attachments/assets/0a06d530-fdfc-40d9-8332-37ea86a3806f)

So immediately we notice a `RANSOM_NOTE.txt`. Taking a look at `world`, we can see that all the region files and the `level.dat` file have been encrypted as well

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

After Ghidra does its analysis, we can see a lot of the same functions we saw in the `.jar` file. This is likely the underlying code for them. We can also see some functions that based on the names, seem to be used to specifically encrypt the Minecraft region and level files
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

Before we do that, I first take a look at what exactly the decrypt function is doing. It seems to go through rounds, uses some kind of constant, and does a lot of xor and bitwise operations. After some research, the ransomware seems to be using a modified version of the TEA/XTEA block cipher. Due to this new info, I retype and rename some variables for easier reading. 

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

So what even is that key? Well, it might be tied to those 2 conditions we found earlier that activates the `encrypt_all_files()` function, specifically the `checker` variable. 

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

So the inputted text needs to be `b4Ckd0Or`. As you can tell by my `key` references in the name of the Python file and in its output, I started to realize that this might actually be the key for the modified TEA/XTEA algorithm in the `decrypt` function in order to decrypt all the encrypted Minecraft files. This is 8 bytes though, and the key needs to be 16 bytes. Perhaps the key is `b4Ckd0Orb4Ckd0Or`? Only one way to find out. 

We can write a C program to call the `decrypt` function from `notsuspicious.so`, but what even are the parameters we need to pass in?

I mean of course we have some hint of this in Ghidra:
![image](https://github.com/user-attachments/assets/b5b945c5-7689-4085-a6d0-e75cb790af3e)

But we can use gdb to be 100% sure. 
