Unpacking CryptOne
==============

CryptOne unpacking method consists of two stages:
* Decrypts and executes embedded shellcode.
* Shellcode decrypts and executes embedded executable.

CryptOne gets chunks of the encrypted data which are separated by junks.

![](images/unpacking/01_crypt1_unpacking.png)

Example Memory Dump:
* **0x5EE00**, Encrypted size.
* **0x4011CA**, Address of encrypted data
* **0x4D/”M”**, Junk data 
* **0x14**, Junk size
* **0x7A**, Chunk Size 

\
Once the “Junks” are removed, the decryption starts with a simple XOR-Key which increases by 0x4 in each round. The initial XOR-Key is **0xA113**.

![](images/unpacking/02_crypt1_unpacking.png)

Once the shellcode is decrypted, we can observe (_“This program cannot be run in DOS mode”_) that those data contained embedded an PE executable which requires a 2nd decryption. 

![](images/unpacking/03_crypt1_unpacking.png)

Similar to previous decryption, this time the shellcode decrypts the embedded binary.

![](images/unpacking/04_crypt1_unpacking.png)

The shellcode allocates and copies the encrypted executable and starts the decryption loop, once it finishes jumps to the EntryPoint and executes the unpacked sample.

![](images/unpacking/05_crypt1_unpacking.png)

At this stage we can observe strings related to the unpacked sample.

![](images/unpacking/06_crypt1_unpacking.png)

This is the unpacking process that the unpacker automates, providing the unpacked sample.
