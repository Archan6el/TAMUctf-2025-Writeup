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

