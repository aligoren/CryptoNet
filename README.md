# CryptoNet

Quick Crypto Lib for .NET (Using public resources)

# Usage

Initilaize Crypto class.

**Sample:**

```csharp
Crypto c = new Crypto();

string hash = c.GeneratePBKDF2Hash("SomeString");

bool validatePassword = c.ValidatePBKDF2Hash("IncorrectString", hash); // false

```


# Supported Cryptographic Functions

AES - 256

Asymmetric RSA

PBKDF2

SHA - 256

XOR

BASE64

# ToDo

 - [ ] - PBKDF2 with SHA 256

 - [ ] - SHA 384

 - [ ] - MD5

 - [ ] - MD4

 - [ ] - MD2

 - [ ] - SHA 512

 - [ ] - SHA 384
