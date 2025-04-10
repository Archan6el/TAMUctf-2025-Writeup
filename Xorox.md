This challenge was a pretty simple XOR rev challenge. 

We are given a binary, `xorox`

Popping it into Ghidra and taking a look at the main function, it seems that the program expects the flag as input. The program loads in some variable `_DAT_00104020` and then takes everything past `gigem` from the flag and passes it to a function `transformation`, 
along with some variable `_DAT_00102080`. If this function returns 1, the program prints "Yup". Otherwise, it prints "Nope"

<details>
  <Summary><i><ins>Click to expand main()</ins></i></Summary>
<div markdown=1>
  
  ```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  undefined local_38 [32];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 2) {
    iVar1 = strncmp((char *)param_2[1],"gigem",5);
    if (iVar1 == 0) {
      vmovdqu_avx(_DAT_00104020);
      local_38 = vmovdqu_avx(_DAT_00102080);
      iVar1 = transformation(param_2[1] + 5,local_38);
      if (iVar1 != 0) {
        puts("Yup");
        uVar2 = 0;
        goto LAB_0010132c;
      }
    }
    puts("Nope");
    uVar2 = 1;
  }
  else {
    printf("Usage: %s <flag>\n",*param_2);
    uVar2 = 1;
  }
LAB_0010132c:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
</div>
</details>

Taking a look at the `transformation` function it seems to load in a new variable, `_DAT_00102060`, and performs some XOR logic with `param_1` and `param_2`, which we know to be everything after `gigem` in the flag and whatever `_DAT_00102080` is respectively. It also performs some XOR logic with whatever is in `in_YMM7` as well, which is probably `_DAT_00104020` which we saw earlier in the main function

<details>
  <Summary><i><ins>Click to expand transformation</ins></i></Summary>
  <div markdown=1>

```c
undefined4 transformation(undefined (*param_1) [32],undefined (*param_2) [32])

{
  long in_FS_OFFSET;
  undefined auVar1 [32];
  undefined auVar2 [32];
  undefined auVar3 [32];
  undefined auVar4 [32];
  undefined in_YMM7 [32];
  
  auVar2 = vmovdqu_avx(_DAT_00102060);
  auVar1 = vmovdqu_avx(*param_2);
  auVar3 = vmovdqu_avx(*param_1);
  auVar4 = vmovdqu_avx(auVar2);
  auVar2 = vpxor_avx2(auVar1,auVar3);
  auVar1 = vpxor_avx2(auVar3,auVar4);
  auVar1 = vpxor_avx2(auVar1,in_YMM7);
  auVar3 = vpaddd_avx2(auVar2,auVar1);
  auVar3 = vpsubd_avx2(auVar3,auVar2);
  vptest_avx(auVar3,auVar3);
  if (*(long *)(in_FS_OFFSET + 0x28) != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(auVar2._0_8_,auVar1._0_8_,auVar3._0_8_);
  }
  return 1;
}
```
</div>
</details>

Well if we look at this XOR logic and analyze it (or have AI do it lol), we find that reversing the XOR logic to find `param_1`, which is the flag, just boils down to:

`param_1 or flag = DAT_00102060 ^ in_YMM7`

As already mentioned, `in_YMM7` is likely `DAT_00104020`, so it's just:

`param_1 or flag = DAT_00102060 ^ DAT_00104020`

We just need the values of `DAT_00104020` and `DAT_00102060` and then we can compute the flag!

We can find that really easily in Ghidra. 

`DAT_00104020` is (this is a partial snippet):

![image](https://github.com/user-attachments/assets/ea87d814-5f2e-4db4-8cc2-c45c3f3cd508)

`_DAT_00102060` is (this is a partial snippet):

![image](https://github.com/user-attachments/assets/600de471-6a59-4a9e-92d5-239edca0a62c)

Now we can write a Python script to reverse the XOR logic:

<details>
<Summary><i><ins>Click to expand xorox-solve.py</ins></i></Summary>
  <div markdown=1>
    
```python
# To get param_1 or the flag, the problem just simplifies to param_1 = DAT_00102060 ^ DAT_00104020
def reverse_transformation(DAT_00102060, DAT_00104020):
    # XOR each byte to recover param_1 (the flag)
    recovered_param_1 = bytes([p ^ c for p, c in zip(DAT_00102060, DAT_00104020)])
    return recovered_param_1

# The value of (DAT_00102060)
DAT_00102060 = bytes.fromhex("fb6ff3cd3a7f8c2aaaca6026f3eec28c92b5a3d761fda1ef5e02902ad2c2dda9")

# The value of (DAT_00104020)
DAT_00104020 = bytes.fromhex("8019c0bf4320ca1e9fbe3f75baa386d3ea85d1e816ccd5870130cf41b7bbaed4")

# Reverse the XOR operation to recover param_1 (which should be the flag)
recovered_param_1 = reverse_transformation(DAT_00102060, DAT_00104020)

# Print the recovered result
print("Recovered param_1:", recovered_param_1)
```
</div>
</details>

Running this gets us:

![image](https://github.com/user-attachments/assets/64adda93-f6fc-4210-b89f-1952b604e00b)

It looks just a tad bit malformed. It seems like it should be `{v3ry_F45t_SIMD_x0r_w1th_2_keys}` instead of `{v3ry_F45t_SIMD_x0r?w1th_2_keys}`. Well, good thing we can check with the binary. If we run `./xorox <flag>` with our probable flag and it's correct, it should print "Yup"

![image](https://github.com/user-attachments/assets/08e6636c-28a5-43e0-9f68-07b8ef3789ac)

Indeed, `gigem{v3ry_F45t_SIMD_x0r_w1th_2_keys}` is the flag!


