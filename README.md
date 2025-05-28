# Symmetry Cryptography
## ECB Oracle

Description
> ECB is the most simple mode, with each plaintext block encrypted entirely independently. In this case, your input is prepended to the secret flag and encrypted and that's it. We don't even provide a decrypt function. Perhaps you don't need a padding oracle when you have an "ECB oracle"?

![image](https://hackmd.io/_uploads/Sk05VJ0sye.png)

* Tư tưởng chính là mã hóa từng block 16 byte thành 32 hex tương ứng

VD: ABCDEFGHIKJLMNOP (16 byte) -> zxcvbnmasdfghjklqwertyuiopqscfgh (32 hex) 


```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


KEY = ?
FLAG = ?


@chal.route('/ecb_oracle/encrypt/<plaintext>/')
def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return {"error": str(e)}

    return {"ciphertext": encrypted.hex()}
```

* Ở đây đoạn code chỉ cho hàm để mã hóa, chứ không cho hàm để giải mã

**Giải thích code**
```
padded = pad(plaintext + FLAG.encode(), 16)
```
* Hàm **pad(data_btye, block_size)** để mở rộng (hiểu đơn giản là nhét chữ) data để đạt độ dài block_size (byte). Mục đích để đảm bảo độ dài data luôn là bội số của 16

VD: 
> pad(b'ab', 6)  ---> b'ab **\x04\x04\x04\x04**'

* Nếu độ dài của data đã là bội của 16, hàm này sẽ tự động thêm vào 16 kí tự nữa (kí tự 'o')

VD: 
> XXXXXXXcrypto{te
> xkhdghakhdkajdt}
> **oooooooooooooooo** (0) <-- padding 16

**Tìm độ dài của flag**
* Thử 'AAAAAAAAAAAA' (6 byte) và cipher text sẽ là: 
> 855bf10aab428df16de163f39d9b665b
> 702bab69dc1be9665a9807fad88ad3d5
> 
![image](https://hackmd.io/_uploads/BJ571s0oJg.png)



* Và khi thử 'AAAAAAAAAAAAAAAA' (7 byte) sẽ ra thêm 1 dòng 32 hex nữa, chứng tỏ khi nhập plaintext có độ dài là 7 byte, thì độ dài của plaintext + flag sẽ là bội của 16 (byte), và 1 dòng thêm kia chính là 1 dòng pad thêm vào
![image](https://hackmd.io/_uploads/r1DF1sRikl.png)




Plaintext + flag (P + F): 
> XXXXXXXcrypto{aa
> dahduiadhuiadh}
> ooooooooooooooo  <-- padding 16

=> Ciphertext ( C ):
> 61e2e16d2b2f76d7cb68bc8511d0d934
> ec103207cd9ee73c84ab8819ebff4505
> 3150f4d79d7cc6c1d4b574b1fce84247 <--- padding of 16

*  2 dòng đầu chính là plaintext + flag được mã hóa dưới dạng hex, 64 hex tương đương 32 byte (1 hex = 2 byte). Mà ta vừa thêm vào 7 byte plaintext nên độ dài của flag suy ra là 32 - 7 = 25 byte

**Brute Force các kí tự trong flag**
* Format sẽ là 'crypto{text}' nên ta chỉ cần đoán xem text là gì.
* Nếu thêm 'AA' (khi đó độ dài plaintext là 8 byte)
P + F:
> XXXXXXXXcrypto{
> adahduiadhuiadh
> }oooooooooooooo

C:
> 9290467e38b839889c380e6ea83745ef 
> cddbe6872f3fcc58b0cc14cfa547d423  
> b260ae79e941ddf896fa63b3d82a184b  <-- }ooooooooooooooo


* Giờ check xem kí tự đầu của dòng cuối có phải đúng là '}' không. Trong bảng ASCII, '}' tương ứng '7d'. Sau khi pad, dòng cuối sẽ có dạng '7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f' (hex). Nên chúng ta sẽ nhập cái này vào để encrypt, ta sẽ có đoạn hex

P + F:
}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f **(16 byte)**
crypto{asdaasdas
dasdasda}ooooooo
C: 

> b260ae79e941ddf896fa63b3d82a184b <-- }ooooooooooooooo
> 4a324f27e8fde012631ac310cce8d626
> 5c4e884ba0ecc2141c276d06247f6b2f

* Và quả nhiên dự đoán ban đầu của chúng ta đã đúng. Nếu cứ thêm kí tự 'AA' vào đằng trước, rồi brute force từng kí tự, ta sẽ thu được flag.

* Ta sẽ target vào kí tự đầu tiên của dòng 3


> XXXXXXXcrypto{te (7 byte plaintext)
> xkhdghakhdkajdt}
> ooooooooooooooo (0)
> 

---

> XXXXXXXXcrypto{t (8 byte plaintext)
> exkhdghakhdkajdt
> }oooooooooooooo (1)
> 

---

> XXXXXXXXXcrypto{ (9 byte plaintext)
> texkhdghakhdkajd
> t}oooooooooooooo (2)


* Khi đó ta sẽ brute force **xx**7d0e0e0e0e0e0e0e0e0e0e0e0e0e0e với **xx** sẽ là các số hex
* Khi tìm được 16 byte cuối của flag, ta sẽ brute force **xx** + 30 hex đầu của flag để tìm nốt 2 kí tự còn lại 

> XXXXXXXXXXXXXXXX (25 byte plaintext)
> XXXXXXXcrypto{te
> **xkhdghakhdkajdt}**  <-- 16 kí tự cuối của flag 
> oooooooooooooooo (3)

Ta chạy nốt 2 vòng để tìm ra 2 kí tự còn lại

> XXXXXXXXXXXXXXXX (26 byte plaintext)
> XXXXXXXXcrypto{t
> e**xkhdghakhdkajdt**  <-- chỉ giữ lại 15 kí tự đầu của flag và brute force
  **}** ooooooooooooooo (4) 



---
> XXXXXXXXXXXXXXXX (27 byte plaintext)
> XXXXXXXXXcrypto{
> te**xkhdghakhdkajd** <-- chỉ giữ lại 14 kí tự đầu của flag và brute force
> **t}** oooooooooooooo (5) 


Sau đây là script
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import requests

# Request encryted from web
def get_request(param):
    r = requests.get('https://aes.cryptohack.org/ecb_oracle/encrypt/' + param)
    data = r.json()['ciphertext']
    return data

# Generate the rest of the third block (padding)
def padding(number):
    time = number
    number = hex(number)[2:]
    if len(number) == 1:
        number = '0' + number
    return number * time

# Find the first character of the third block
def extract(i):
    for w in word_list:
        if len(flag) < 32:
            inp = w + flag + padding(i) # String 32 hex
            first_block = get_request(inp)[:32]
            print('testing', inp)
            if first_block == block:
                return w
        else:
            inp = w + flag[:30]
            first_block = get_request(inp)[:32]
            print('testing', inp)
            if first_block == block:
                return w

# Generate word list        
word_list = []
for i in range(32, 127):
    word = hex(i)[2:]
    if len(word) == 1:
        word = '0' + word
    word_list.append(word)

flag = ''

# Find the last 16 byte of flag
for i in range(15, -1, -1):
    offset = 16 - i
    added = 'AA' * 7 + 'AA' * offset
    block = get_request(added)[64:96] # Check on the third block 
    flag = extract(i) + flag

flag = '6e3675316e355f683437335f3363627d'

# Check the first 2 characters of the text
for i in range(2):
    offset = 17 + i
    added = 'AA' * 7 + 'AA' * offset
    block = get_request(added)[64:96] # Check on the third block 
    flag = extract(i) + flag

flag = '70336e3675316e355f683437335f3363627d' # hex
# p3n6u1n5_h473_3cb} in byte
# flag = crypto{p3n6u1n5_h473_3cb}
```

## ECB CBC WTF
> Here you can encrypt in CBC but only decrypt in ECB. That shouldn't be a weakness because they're different modes... right?

![image](https://hackmd.io/_uploads/HkKNxuUhke.png)

Source
```
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/ecbcbcwtf/decrypt/<ciphertext>/')
def decrypt(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


@chal.route('/ecbcbcwtf/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}

```

* Ciphertext = mã hóa (iv + plaintext1 + plaintext2)

```
import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long

# len(iv) = 16, len(flag) = 32, p1 = 16, p2 = 16 in bytes
def encrypted():
    url = 'https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/'
    ciphertext = requests.get(url)
    return bytes.fromhex(ciphertext.json()['ciphertext'])

def decrypted(ciphertext):
    ciphertext =  ciphertext.hex()
    url = 'https://aes.cryptohack.org/ecbcbcwtf/decrypt/' + ciphertext
    plaintext = requests.get(url)
    return bytes.fromhex(plaintext.json()['plaintext'])

def xor(text1, text2):
    return long_to_bytes(bytes_to_long(text1) ^ bytes_to_long(text2))

ciphertext = encrypted()

iv = ciphertext[:16]
ciphertext1 = ciphertext[16:32]
ciphertext2 = ciphertext[32:]

# dn = pn ^ c(n-1) (c0 = iv)
decrypted1_xor = decrypted(ciphertext1)
decrypted2_xor = decrypted(ciphertext2)

p2 = xor(decrypted2_xor, ciphertext1)
p1 = xor(iv, decrypted1_xor)
plaintext = p1 + p2
print(plaintext.decode())

# flag = crypto{3cb_5uck5_4v01d_17_!!!!!}


```


## Flipping Cookie

> Description
> You can get a cookie for my website, but it won't help you read the flag... I think.

![image](https://hackmd.io/_uploads/SyIsx_I3kg.png)

Source

```
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta


KEY = ?
FLAG = ?


@chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}


@chal.route('/flipping_cookie/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}
```

Trong hàm **check_admin()**, cookie phải có "admin=True" thì ta mới thu được FLAG. Vậy ta chỉ cần biến đổi cookie từ **get_cookie()** từ "admin=False" thành cái ta cần bằng phép xor

```
Pt = b'admin=False;expi'
Pf = b'admin=True;\x05\x05\x05\x05\x05'
Pm = xor(Pt, Pf)
new_iv = xor(bytes.fromhex(iv), Pm)
```

![image](https://hackmd.io/_uploads/S1jns7X3kl.png)

Code
```
from Crypto.Cipher import AES
import requests
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from Crypto.Util.number import long_to_bytes, bytes_to_long

def get_cookie():
    url = 'https://aes.cryptohack.org/flipping_cookie/get_cookie/'
    iv_cookie = requests.get(url).json()['cookie']
    iv = iv_cookie[:32]
    cookie = iv_cookie[32:]
    return cookie, iv

def decrypted(cookie, iv):
    url = 'https://aes.cryptohack.org/flipping_cookie/check_admin/' + cookie + '/' + iv
    decrypted = requests.get(url)
    return decrypted.json()

def xor(byte1, byte2):
    return long_to_bytes(bytes_to_long(byte1) ^ bytes_to_long(byte2))

cookie, iv = get_cookie()
block1 = bytes.fromhex(cookie[:32])
block2 = cookie[32:]


Pt = b'admin=False;expi'
Pf = b'admin=True;\x05\x05\x05\x05\x05'
Pm = xor(Pt, Pf)
new_iv = xor(bytes.fromhex(iv), Pm)

print(decrypted(block1.hex(), new_iv.hex()))

# flag = crypto{4u7h3n71c4710n_15_3553n714l}
```

## Symmetry

> Some block cipher modes, such as OFB, CTR, or CFB, turn a block cipher into a stream cipher. The idea behind stream ciphers is to produce a pseudorandom keystream which is then XORed with the plaintext. One advantage of stream ciphers is that they can work of plaintext of arbitrary length, with no padding required.
OFB is an obscure cipher mode, with no real benefits these days over using CTR. This challenge introduces an unusual property of OFB.

![image](https://hackmd.io/_uploads/B1WOcw8hye.png)


Source
```
from Crypto.Cipher import AES


KEY = ?
FLAG = ?


@chal.route('/symmetry/encrypt/<plaintext>/<iv>/')
def encrypt(plaintext, iv):
    plaintext = bytes.fromhex(plaintext)
    iv = bytes.fromhex(iv)
    if len(iv) != 16:
        return {"error": "IV length must be 16"}

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext)
    ciphertext = encrypted.hex()

    return {"ciphertext": ciphertext}


@chal.route('/symmetry/encrypt_flag/')
def encrypt_flag():
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}
```

* Ở đây đề bài cho 2 hàm **encrypt()** và **encrypt_flag()**, ta nghĩ đến việc đánh vào lỗ hổng đầu vào 

![image](https://hackmd.io/_uploads/By2-Cw8hJe.png)

* Ta sẽ khéo léo chọn plaintext (Pk) bất kì rồi cho vào hàm **encrypt()**, sau đó lấy kết quả xor với ciphertext của flag, ta sẽ thu được kết quả (khi đó sẽ mất hết cái đống e(iv)). 

* Ta chọn Pk = '00' * 33 trùng với độ dài của ciphertext flag, mục đích là khi cho vào phép xor, '00' sẽ không làm thay đổi các bits. Có thể chọn các kí tự khác, nhưng sẽ phải xor tiếp với chính Pk thì mới thu được kết quả.

```
from Crypto.Cipher import AES
import os
import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long

def encrypt_flag():
    url = 'https://aes.cryptohack.org/symmetry/encrypt_flag/'
    ciphertext = requests.get(url)
    return ciphertext.json()['ciphertext']

def encrypt(plaintext, iv):
    url = url = f'https://aes.cryptohack.org/symmetry/encrypt/{plaintext}/{iv}/'
    ciphertext = requests.get(url)
    return ciphertext.json()['ciphertext']

def xor(text1, text2):
    return bytes(a ^ b for a, b in zip(text1, text2))

# flag = 2 block 16 + 1 block 1

flag_ciphertext = encrypt_flag()
iv = flag_ciphertext[:32]  
ciphertext = flag_ciphertext[32:]

known_plaintext = '00' * (len(ciphertext) // 2)
known_ciphertext = bytes.fromhex(encrypt(known_plaintext, iv))

ciphertext = bytes.fromhex(ciphertext)
plaintext = xor(ciphertext, known_ciphertext)
print(plaintext.decode())

# flag = crypto{0fb_15_5ymm37r1c4l_!!!11!}
```

## Bean Counter

> I've struggled to get PyCrypto's counter mode doing what I want, so I've turned ECB mode into CTR myself. My counter can go both upwards and downwards to throw off cryptanalysts! There's no chance they'll be able to read my picture.

![image](https://hackmd.io/_uploads/HkfoDwd31x.png)

Source
```
from Crypto.Cipher import AES


KEY = ?


class StepUpCounter(object):
    def __init__(self, step_up=False):
        self.value = os.urandom(16).hex()
        self.step = 1
        self.stup = step_up

    def increment(self):
        if self.stup:
            self.newIV = hex(int(self.value, 16) + self.step)
        else:
            self.newIV = hex(int(self.value, 16) - self.stup)
        self.value = self.newIV[2:len(self.newIV)]
        return bytes.fromhex(self.value.zfill(32))

    def __repr__(self):
        self.increment()
        return self.value



@chal.route('/bean_counter/encrypt/')
def encrypt():
    cipher = AES.new(KEY, AES.MODE_ECB)
    ctr = StepUpCounter()

    out = []
    with open("challenge_files/bean_flag.png", 'rb') as f:
        block = f.read(16)
        while block:
            keystream = cipher.encrypt(ctr.increment())
            xored = [a^b for a, b in zip(block, keystream)]
            out.append(bytes(xored).hex())
            block = f.read(16)

    return {"encrypted": ''.join(out)}
```

* Đại loại là thay vì encrypt một giá trị iv cố định, thì với mode này ta sẽ encrypt những giá trị thay đổi
* Nhưng ở hàm **increment** trong class **StepUpCounter**, ở phần else (if False), giá trị của newIV là hex(int(self.value, 16) -  self.stup), nhưng self.stup không đổi (luôn là False) và bằng 0, nên coi như newIV sẽ luôn giữ giá trị cố định.
* 32 hex (16 bytes) đầu của một file png (signature bytes) luôn là '89504E470D0A1A0A0000000D49484452'.
* Ta sẽ xor signature bytes với 16 bytes đầu của ciphertext để thu được newIV, sau đó ta sẽ mở rộng độ dài newIV bằng độ dài ciphertext, và xor với ciphertext

Code
```
import requests
import os
import webbrowser

def encrypt():
    url = 'https://aes.cryptohack.org/bean_counter/encrypt/'
    response = requests.get(url)
    return bytes.fromhex(response.json()['encrypted'])

def xor(text1, text2):
    return bytes(a^b for a,b in zip(text1, text2))

ciphertext = encrypt()
image_header = bytes.fromhex('89504E470D0A1A0A0000000D49484452')
first_16_byte = ciphertext[:16]
encrypted_iv = xor(image_header, first_16_byte)
repeat_count = len(ciphertext) // 16 + 1  # +1 để đảm bảo đủ dài
encrypted_iv = (encrypted_iv * repeat_count)[:len(ciphertext)]
decrypted_data = xor(encrypted_iv, ciphertext)
print(decrypted_data[:50])

with open("decrypted.png", "wb") as f:
    f.write(decrypted_data)

os.system("decrypted.png")

# flag = crypto{hex_bytes_beans}
```



# Public-Key Cryptography
## Factoring
> So far we've been using the product of small primes for the modulus, but small primes aren't much good for RSA as they can be factorised using modern methods.

> What is a "small prime"? There was an RSA Factoring Challenge with cash prizes given to teams who could factorise RSA moduli. This gave insight to the public into how long various key sizes would remain safe. Computers get faster, algorithms get better, so in cryptography it's always prudent to err on the side of caution.

> These days, using primes that are at least 1024 bits long is recommended—multiplying two such 1024 primes gives you a modulus that is 2048 bits large. RSA with a 2048-bit modulus is called RSA-2048.

> Some say that to really remain future-proof you should use RSA-4096 or even RSA-8192. However, there is a tradeoff here; it takes longer to generate large prime numbers, plus modular exponentiations are predictably slower with a large modulus.

> Factorise the 150-bit number 510143758735509025530880200653196460532653147 into its two constituent primes. Give the smaller one as your answer.

> Resources:
>   - How big an RSA key is considered secure today?
>   - primefac-fork
> 

* Cho vào factordb.com

![image](https://hackmd.io/_uploads/B1Zgbwc3kg.png)

flag = 19704762736204164635843

## Parameter Injection
> You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages. Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any discrete logarithm problem.
Use the script from "Deriving Symmetric Keys" to decrypt the flag once you've recovered the shared secret.
Connect at socket.cryptohack.org 13371

* Request lên server: nc socket.cryptohack.org 13371 thì trả về Alice: {"A": "...", "g": "...", "p": "..."}, ta sẽ gửi lại cho Bob: {"A": "...", "g": "...", "p": "...", "B":: "1"} 
* **share_secrete** dùng để tạo key
* Ép cho **share_secrete** = 1


## Export-grade
> Alice and Bob are using legacy codebases and need to negotiate parameters they both support. You've man-in-the-middled this negotiation step, and can passively observe thereafter. How are you going to ruin their day this time?
Connect at socket.cryptohack.org 13379

* Ép cho Bob và Alice dùng những công cụ cổ lỗ sĩ và dễ phá (xài luôn DH64)
![image](https://hackmd.io/_uploads/Hy-JdxlpJl.png)


Sau đó đưa vào SageMath để tìm ngược lại a và giải mã như các bài trước
```
from sage.all import *
p = 16007670376277647657
g = 2
A = 2119244814031586549
B = 14079643880278902881
iv = 324104172547876919393920735098535650727       
encrypted_flag = 79922508758654581450158766164873195188555249414776703458170512760214674484503
F = GF(p)
g = F(g)
A = F(A)
x = discrete_log(A, g)
print(f'Private key (x) = {x}')
# Private key (x) = 3594150914192704739
```
Code
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from math import gcd
from sympy import mod_inverse


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

p = "0xde26ab651b92a129"
g = "0x2"
A = "0x1d6911ee1c7104f5"
B = "0xc364f1831006c861"
iv = "f3d4316f128901a664b7cbc96d57a5a7"
encrypted_flag = "b0b28972a8e2ad323a71fa5b6ab23805600c3180ffc42142aff9586a24482d17"

p = int(p, 16)
g = int(g, 16)
A = int(A, 16)
B = int(B, 16)
a = 3594150914192704739
shared_secret = pow(B, a, p)
print(decrypt_flag(shared_secret, iv, encrypted_flag))

#flag = crypto{d0wn6r4d35_4r3_d4n63r0u5}

```

## Oh SNAP
Description
> Here's the start of my fast network authentication protocol, so far I've only implemented the "Ping" command so there shouldn't be any way to recover the key.

Source


```
from Crypto.Cipher import ARC4


FLAG = ?


@chal.route('/oh_snap/send_cmd/<ciphertext>/<nonce>/')
def send_cmd(ciphertext, nonce):
    if not ciphertext:
        return {"error": "You must specify a ciphertext"}
    if not nonce:
        return {"error": "You must specify a nonce"}

    ciphertext = bytes.fromhex(ciphertext)
    nonce = bytes.fromhex(nonce)

    cipher = ARC4.new(nonce + FLAG.encode())
    cmd = cipher.decrypt(ciphertext)
    if cmd == b"ping":
        return {"msg": "Pong!"}
    else:
        return {"error": f"Unknown command: {cmd.hex()}"}
```

* RC4 Cipher: Tạo ra keystream từ key và S_box, gồm có 2 bước
**Key-scheduling algorithm (KSA) và Pseudo-random generation algorithm (PRGA)** 
```
def ksa(k: bytes, rounds: int = N) -> list[int]:
    S = list(range(N)) # identity permutation
    j = 0
    for i in range(rounds):
        j = (j + S[i] + k[i % len(k)]) % N
        S[i], S[j] = S[j], S[i] # swap

    return j, S

def prga(S: list[int]):
    i = j = 0
    while 1:
        i = (i + 1) % N
        j = (j + S[i]) % N
        S[i], S[j] = S[j], S[i]

        z = S[(S[i] + S[j]) % N]
        yield z
        
def decrypt(ct: bytes, key: bytes):
    _, S = ksa(key)
    stream = prga(S)
    return bytes(a ^ b for a, b in zip(ct, stream))
```

* **FMS Attack:**
Chúng ta sẽ đánh vào điểm yếu của RC4 về sự phân bổ không đồng đều của S_box. Cụ thể là khi chọn nonce trong key = nonce || secret yếu, có dạng (A + 3, n - 1, x), trong đó A là index của byte cần tìm của secret, n là 256 để j ít thay đổi, x là giá trị bất kì trong [0, 255]

Và ta sẽ khai thác từ công thức j(i+1) = j(i) + S[i] + K[i % len(K)], trong đó KS[i] là keystream tại index i, K[i] là key = nonce || secret tại vị trí i

**=> K[i] = j(i+1) - j(i) - S[i]**

Giả sử nonce = [3, 255, 1]
khi đó key = [3, 255, 1, x,...]

S_box = [0, 1, 2, 3,..., 255]

- i = 0, j = 0 + 0 + 3
S_box = [3, 1, 2, 0,.., 255]

- i = 1, j = (1 + 255 + 3) % 256 = 3
S_box = [3, 0, 2, 1,..., 255]

- i = 2, j = 1 + 3 + 2 = 6
S_box = [3, 0, 6, 1, 4, 5, 2, 7,..., 255]

- i = 3, j = x + 1 + 6 = x', S[x'] = x'
S_box = [3, 0, 6, x', 4, 5, 2, 7,..., 1,..., 255]

Khi đi qua **prga**, ta sẽ thu được KS[0] = S[S[0] + S[1]] = S[3] = x' (đây chính là j(i+1))

=> **=> K[i] = KS[0] - j(i) - S[i]**

Mà keystream = ciphertext ^ plaintext, nên ý tưởng sẽ là khôi phục lại key từ keystream và các chỉ số, và trạng thái của S_box

* Tại sao lại làm theo cách này được ?
Đây cũng chính là điểm yếu của RC4, tỉ lệ S[0], S[1] và S[3] vẫn ở nguyên index sau 252 vòng lặp nữa sẽ là  

Trong bài cho phép chúng ta gửi giá trị nonce và ciphertext bất kì. Ta sẽ chọn ciphertext = b'\x00' là 00 trong hex để xor với plaintext sẽ ra keystream[0].

Với mỗi byte của flag, ta sẽ cho x chạy từ 0 - 255, byte nào có tần suất xuất hiện nhiều nhất sẽ là byte của flag (thử nhập nonce có độ dài 222 thì server vẫn trả về kết quả, nhưng 223 thì server báo lỗi, có thể độ dài của flag sẽ là 256 - 222 = 34)

Code:
```
import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import ARC4
from collections import Counter

def send_cmd(ciphertext, nonce):
    url = 'https://aes.cryptohack.org/oh_snap/send_cmd/' + ciphertext + '/' + nonce
    response = requests.get(url)
    return response.json()['error'][17:]

def xor(byteA, byteB):
    return long_to_bytes(bytes_to_long(byteA) ^ bytes_to_long(byteB))

def simulate_S_box(key, A):
    key = [int(key.hex()[i * 2: i * 2 + 2], 16) for i in range(len(key))] # Convert nonce into list
    S = [i for i in range(256)]
    j = 0
    for i in range(A + 3):
        j = (j + S[i % 256] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = A + 2
    return S[i+1], j # Return S[i] and j of last KSA round

ciphertext = b'\x00'.hex()
length_key = 34
nonce = bytes([3, 255, 1])
plaintext = send_cmd(ciphertext, nonce.hex())
keystream = xor(bytes.fromhex(plaintext), bytes.fromhex(ciphertext))
known = b'crypto{'

for A in range(7, length_key):
    possible_key = [] # Store all possible value of key, pick the most frequent item
    for v in range(256):
        nonce = bytes([A + 3, 255, v])
        key = nonce + known
        plaintext = send_cmd(ciphertext, nonce.hex())
        keystream = xor(bytes.fromhex(plaintext), bytes.fromhex(ciphertext))
        s_i, j = simulate_S_box(key, A)
        possible_key_fragment = (keystream[0] - s_i - j) % 256
        print(v, chr(possible_key_fragment))
        possible_key.append(possible_key_fragment)
    counter = Counter(possible_key)
    key_fragment = chr(counter.most_common(1)[0][0])
    known += key_fragment.encode()
    print(key_fragment, known)


# flag = crypto{w1R3d_equ1v4l3nt_pr1v4cy?!}
```



## Pad Thai
> Sometimes the classic challenges can be the most delicious
> 
> Connect at socket.cryptohack.org 13421
> 
> Challenge files:
>   - 13421.py
> 

13221.py
```
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom

from utils import listener

FLAG = 'crypto{?????????????????????????????????????????????????????}'

class Challenge:
    def __init__(self):
        self.before_input = "Let's practice padding oracle attacks! Recover my message and I'll send you a flag.\n"
        self.message = urandom(16).hex()
        self.key = urandom(16)

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return {"ct": (iv+ct).hex()}

    def check_padding(self, ct):
        ct = bytes.fromhex(ct)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)  # does not remove padding
        try:
            unpad(pt, 16)
        except ValueError:
            good = False
        else:
            good = True
        return {"result": good}

    def check_message(self, message):
        if message != self.message:
            self.exit = True
            return {"error": "incorrect message"}
        return {"flag": FLAG}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, msg):
        if "option" not in msg or msg["option"] not in ("encrypt", "unpad", "check"):
            return {"error": "Option must be one of: encrypt, unpad, check"}

        if msg["option"] == "encrypt": return self.get_ct()
        elif msg["option"] == "unpad": return self.check_padding(msg["ct"])
        elif msg["option"] == "check": return self.check_message(msg["message"])

import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13421)
```

* Nói qua một chút về đoạn code của đề bài, mỗi lần khởi động challenge sẽ sinh ra đoạn message 32 hex, sau đó message đó sẽ được chuyển thành 32 byte và được mã hóa, nhiệm vụ của ta sẽ phải khôi phục đoạn message đó
* Hàm **unpad(message, byte)** sẽ loại bỏ đi các pad dư thừa ở các khối plaintext. Ta có thể lợi dụng hàm này để khôi phục lại đoạn message

![image](https://hackmd.io/_uploads/rJZk4Ygbxg.png)


CBC mode operation

![image](https://hackmd.io/_uploads/S1EmQtxbel.png)


* Ta có thể tự do điều chỉnh iv và ciphertext (input) ta sẽ chọn iv sao cho P1[15] = b'\x01' để unpad valid

![image](https://hackmd.io/_uploads/S1BREtebll.png)
* Và khi đó ta sẽ khôi phục lại d(C1)[15] (trong đó d(C1) là ciphertext sau khi đi qua hàm decrypt), làm lần lượt với các kí tự còn lại. Sau khi thu được d(C1) hoàn chỉnh thì ta cho xor với iv ban đầu để ra P1. Sau đó làm tương tự với C2, chỉ khác bước cuối thay vì xor với iv thì ta sẽ cho xor với C1.

Code:
```
    from pwn import *
    import json

    def oracle(iv, ct):
        ct = (iv + ct).hex()
        conn.sendline(json.dumps({"option": "unpad", "ct": ct}).encode())
        res = json.loads(conn.recvline().decode())
        print(len(iv), iv, res)
        return res['result']

    def attack_block(iv, ciphertext):
        known_dct = b''
        for i in range(16): # For each character in a block
            padding = (i+1).to_bytes(1, 'big') * (i+1)
            for guess in range(256): 
                known_fake = xor(bytes([guess]) + known_dct, padding)
                fake_iv = bytes(15 - i) + known_fake
                if oracle(fake_iv, ciphertext):
                    known_dct = bytes([guess]) + known_dct
                    print("FOUND", known_dct)
                    break
        return xor(iv, known_dct)

    def attack(iv, c1, c2):
        p = attack_block(iv, c1)
        p += attack_block(c1, c2)
        return p

    conn = remote('socket.cryptohack.org', 13421)
    print(conn.recvline().decode())

    # Take ciphertext
    payload1 = {"option": "encrypt"}
    conn.sendline(json.dumps(payload1).encode())
    line = conn.recvline(timeout=5)
    data = json.loads(line.decode())['ct']
    data = bytes.fromhex(data)
    iv = data[:16]
    ct = data[16:]
    c1 = ct[:16]
    c2 = ct[-16:]

    plaintext = attack(iv, c1, c2)
    conn.sendline(json.dumps({"option":"check", "message": plaintext.decode()}).encode())
    print(conn.recvline())
```

## The good, the pad, the ugly

> The first twist of the classic challenge, how can you handle an oracle with errors?
> 
> Connect at socket.cryptohack.org 13422
> 
> Challenge files:
>   - 13422.py

13422.py
```
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
from random import SystemRandom

from utils import listener

FLAG = 'crypto{??????????????????????????????????????????}'
rng = SystemRandom()


class Challenge:
    def __init__(self):
        self.before_input = "That last challenge was pretty easy, but I'm positive that this one will be harder!\n"
        self.message = urandom(16).hex()
        self.key = urandom(16)
        self.query_count = 0
        self.max_queries = 12_000

    def update_query_count(self):
        self.query_count += 1
        if self.query_count >= self.max_queries:
            self.exit = True

    def get_ct(self):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(self.message.encode("ascii"))
        return {"ct": (iv+ct).hex()}

    def check_padding(self, ct):
        ct = bytes.fromhex(ct)
        iv, ct = ct[:16], ct[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)  # does not remove padding
        try:
            unpad(pt, 16)
        except ValueError:
            good = False
        else:
            good = True
        self.update_query_count()
        return {"result": good | (rng.random() > 0.4)}

    def check_message(self, message):
        if message != self.message:
            self.exit = True
            return {"error": "incorrect message"}
        return {"flag": FLAG}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, msg):
        if "option" not in msg or msg["option"] not in ("encrypt", "unpad", "check"):
            return {"error": "Option must be one of: encrypt, unpad, check"}

        if msg["option"] == "encrypt": return self.get_ct()
        elif msg["option"] == "unpad": return self.check_padding(msg["ct"])
        elif msg["option"] == "check": return self.check_message(msg["message"])


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13422)
```
Đây là một bài toán về tấn công thống kê

* Bài này giống Pad Thai, có điều khi ta nhìn vào hàm **check_padding()** thì kết quả trả về là return {"result": good l (rng.random() > 0.4)} (And operation)
Tỉ lệ trả về True của rng là 0,6 trong khi False là 0,4

* Nếu kết quả trả về False, thì chắn chắn sai (False | False)
* Còn nếu kết quả True thì sẽ có các khả năng (True | False), (True | True) là các trường hợp đúng và (False | True) là trường hợp dương tính giả, khi kết quả trả về True thì ta phải check xem có đúng không bằng cách thử lại nhiều lần, nhưng bao nhiêu là đủ ?

* Xác suất sai khi rng trả về True là P = $0,6^n$
Max ping đề cho chạy 12000 queries, mà có 32 byte => Tối đa mỗi byte có thể chạy 120000 / 32 = 375 queries, hãy nhìn vào message, nó ở dưới dạng hex (0123...f), tức ta chỉ cần thử 16 giá trị => Max ping ta có thể thử để trả về 375 / 16 = 23 lần True để chắc chắn rằng đó là byte đúng, và xác suất sai sẽ là $0,6^{23}$ = 7.89730223053602e-06 rất rất nhỏ

Code:
```
from pwn import *
import json
from Crypto.Util.strxor import strxor

def oracle(prev, ct):
    ct = (prev + ct).hex()
    conn.sendline(json.dumps({"option": "unpad", "ct": ct}).encode())
    res = json.loads(conn.recvline().decode())
    print(len(prev), prev, res)
    return res['result']

def check(prev, ct):
    for i in range(23):
        if not oracle(prev, ct):
            return False
    return True

def attack_block(prev, ciphertext):
    possible_guess = b'0123456789abcdef'
    known_dct = bytearray(16)
    plaintext = bytearray(16)
    for i in range(15, -1, -1):
        pad_val = 16 - i
        for char in possible_guess:
            guess = char ^ pad_val ^ prev[i]
            prefix = bytes(i)
            middle = bytes([guess])
            suffix = bytes([known_dct[j] ^ pad_val for j in range(i + 1, 16)])
            fake_prev = prefix + middle + suffix
            if check(fake_prev, ciphertext):
                known_dct[i] = guess ^ pad_val
                plaintext[i] = known_dct[i] ^ prev[i]
                print("FOUND", known_dct)
                break
    return bytes(plaintext)

def attack(iv, c1, c2):
    p = attack_block(iv, c1)
    p += attack_block(c1, c2)
    return p

conn = remote('socket.cryptohack.org', 13422)
print(conn.recvline().decode())

# Take ciphertext
payload1 = {"option": "encrypt"}
conn.sendline(json.dumps(payload1).encode())
line = conn.recvline(timeout=5)
data = json.loads(line.decode())['ct']
data = bytes.fromhex(data)
iv = data[:16]
ct = data[16:]
c1 = ct[:16]
c2 = ct[-16:]

plaintext = attack(iv, c1, c2)
conn.sendline(json.dumps({"option":"check", "message": plaintext.decode()}).encode())
print(conn.recvline())
```


![image](https://hackmd.io/_uploads/S1-2OVVWxx.png)

![image](https://hackmd.io/_uploads/S1GeKVN-xg.png)

iv(f) là prev_fake
iv(r) là prev
p là char

** Crossed Wires
> I asked my friends to encrypt our secret flag before sending it to me, but instead of using my key, they've all used their own! Can you help?
> 
> Challenge files:
>   - source.py
>   - output.txt
> 
> Resources:
>   - RSA: how to factorize N given d

source.py
```
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long, inverse
import math
from gmpy2 import next_prime

FLAG = b"crypto{????????????????????????????????????????????????}"

p = getPrime(1024)
q = getPrime(1024)
N = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = inverse(e, phi)

my_key = (N, d)

friends = 5
friend_keys = [(N, getPrime(17)) for _ in range(friends)]

cipher = bytes_to_long(FLAG)

for key in friend_keys:
    cipher = pow(cipher, key[1], key[0])

print(f"My private key: {my_key}")
print(f"My Friend's public keys: {friend_keys}")
print(f"Encrypted flag: {cipher}")
```

* Ở đây ta thấy FLAG sẽ được raise mũ tận 5 lần, c = $m^{e1*e2*e3*e4*e5}$ mod N <=> c = $m^x$ mod N

 * Ta có ed - 1 = k * phi(N) (cái này đóng vai trò như phi(N)) thế nên không cần phải tìm p, q, từ đó tìm ngược lại được y = d = $x^{-1}$ mod phi(N)

Code
```
from Crypto.Util.number import long_to_bytes, inverse

e = '0x10001'
e = int(e, 16)
N, d = (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 2734411677251148030723138005716109733838866545375527602018255159319631026653190783670493107936401603981429171880504360560494771017246468702902647370954220312452541342858747590576273775107870450853533717116684326976263006435733382045807971890762018747729574021057430331778033982359184838159747331236538501849965329264774927607570410347019418407451937875684373454982306923178403161216817237890962651214718831954215200637651103907209347900857824722653217179548148145687181377220544864521808230122730967452981435355334932104265488075777638608041325256776275200067541533022527964743478554948792578057708522350812154888097)

e_friend = 1
friends = 5
friend_keys = [(21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 106979), (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 108533), (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 69557), (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 97117), (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, 103231)]

for (i, j) in friend_keys:
    e_friend *= j

d_friend = inverse(e_friend, e*d - 1)
cipher = 20304610279578186738172766224224793119885071262464464448863461184092225736054747976985179673905441502689126216282897704508745403799054734121583968853999791604281615154100736259131453424385364324630229671185343778172807262640709301838274824603101692485662726226902121105591137437331463201881264245562214012160875177167442010952439360623396658974413900469093836794752270399520074596329058725874834082188697377597949405779039139194196065364426213208345461407030771089787529200057105746584493554722790592530472869581310117300343461207750821737840042745530876391793484035024644475535353227851321505537398888106855012746117


print(long_to_bytes(pow(cipher, d_friend, N)))
```
 
 
 ## Square eyes
>  It was taking forever to get a 2048 bit prime, so I just generated one and used it twice.
> 
>  If you're stuck, look again at the formula for Euler's totient.
> 
> 
> Challenge files:
>   - output.txt

* Khi ta phân tích n thì sẽ thu được n là bình phương của 1 số p

![image](https://hackmd.io/_uploads/ByEpllQfll.png)

* Đây là công thức của hàm phi, dựa vào đây ta sẽ thu được phi của bài này có công thức như sau

![image](https://hackmd.io/_uploads/r1pfZemGll.png)


* Sai lầm khi nghĩ rằng phi bài này sẽ bằng phi(n) = $(p-1) ^ {2}$

## Everything is Big
> We have a supercomputer at work, so I've made sure my encryption is secure by picking massive numbers!
> 
> Challenge files:
>   - source.py
>   - output.txt

source.py
```
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"crypto{?????????????????????????}"

m = bytes_to_long(FLAG)

def get_huge_RSA():
    p = getPrime(1024)
    q = getPrime(1024)
    N = p*q
    phi = (p-1)*(q-1)
    while True:
        d = getPrime(256)
        e = pow(d,-1,phi)
        if e.bit_length() == N.bit_length():
            break
    return N,e


N, e = get_huge_RSA()
c = pow(m, e, N)

print(f'N = {hex(N)}')
print(f'e = {hex(e)}')
print(f'c = {hex(c)}')
```

* Bài này cho e khá lớn, ta có thể nghĩ đến việc dùng wiener vì d khả năng sẽ nhỏ

* Wiener's Attack
ed đồng dư 1 mod phi(n)
<=> ed - 1 = k * phi(n) 
~ed = k * phi(n) 
<=> e / phi(n) = k / d 
~e / n = k / d (do phi(n) = N - (p + q) + 1)

Ý tưởng là sẽ đi tìm k và d bằng cách tìm phân số xấp xỉ (convergent) với e / n dựa vào [Continued fraction](https://en.wikipedia.org/wiki/Continued_fraction)
![image](https://hackmd.io/_uploads/SJTn0V7zgg.png)
(Đối với Wiener's Attack thì mấy cái a kia chỉ là 1)

Sau đó sẽ kiểm tra phi(n) = (ed - 1) / k có phải là số nguyên hay không, nếu có, kiểm tra tiếp phương trình

Bước này biến đổi
(x - p)(x - q) = 0
<=> $x^2$ - (p + q)x + pq = 0
<=> $x^2$ - (N + 1 - phi(n))x + N = 0 có nghiệm nguyên hay không, nếu có thì đây chính là p, q

Code
```
import owiener
from Crypto.Util.number import long_to_bytes

N = 0xb8af3d3afb893a602de4afe2a29d7615075d1e570f8bad8ebbe9b5b9076594cf06b6e7b30905b6420e950043380ea746f0a14dae34469aa723e946e484a58bcd92d1039105871ffd63ffe64534b7d7f8d84b4a569723f7a833e6daf5e182d658655f739a4e37bd9f4a44aff6ca0255cda5313c3048f56eed5b21dc8d88bf5a8f8379eac83d8523e484fa6ae8dbcb239e65d3777829a6903d779cd2498b255fcf275e5f49471f35992435ee7cade98c8e82a8beb5ce1749349caa16759afc4e799edb12d299374d748a9e3c82e1cc983cdf9daec0a2739dadcc0982c1e7e492139cbff18c5d44529407edfd8e75743d2f51ce2b58573fea6fbd4fe25154b9964d
e = 0x9ab58dbc8049b574c361573955f08ea69f97ecf37400f9626d8f5ac55ca087165ce5e1f459ef6fa5f158cc8e75cb400a7473e89dd38922ead221b33bc33d6d716fb0e4e127b0fc18a197daf856a7062b49fba7a86e3a138956af04f481b7a7d481994aeebc2672e500f3f6d8c581268c2cfad4845158f79c2ef28f242f4fa8f6e573b8723a752d96169c9d885ada59cdeb6dbe932de86a019a7e8fc8aeb07748cfb272bd36d94fe83351252187c2e0bc58bb7a0a0af154b63397e6c68af4314601e29b07caed301b6831cf34caa579eb42a8c8bf69898d04b495174b5d7de0f20cf2b8fc55ed35c6ad157d3e7009f16d6b61786ee40583850e67af13e9d25be3
c = 0x3f984ff5244f1836ed69361f29905ca1ae6b3dcf249133c398d7762f5e277919174694293989144c9d25e940d2f66058b2289c75d1b8d0729f9a7c4564404a5fd4313675f85f31b47156068878e236c5635156b0fa21e24346c2041ae42423078577a1413f41375a4d49296ab17910ae214b45155c4570f95ca874ccae9fa80433a1ab453cbb28d780c2f1f4dc7071c93aff3924d76c5b4068a0371dff82531313f281a8acadaa2bd5078d3ddcefcb981f37ff9b8b14c7d9bf1accffe7857160982a2c7d9ee01d3e82265eec9c7401ecc7f02581fd0d912684f42d1b71df87a1ca51515aab4e58fab4da96e154ea6cdfb573a71d81b2ea4a080a1066e1bc3474

d = owiener.attack(e, N)

print(long_to_bytes(pow(c, d, N)))
```

## Endless Emails
```
Poor Johan has been answering emails all day and many of the students are asking the same question. Can you read his messages?

Challenge files:
  - johan.py
  - output.txt
```

johan.py
```
from Crypto.Util.number import bytes_to_long, getPrime
from secret import messages


def RSA_encrypt(message):
    m = bytes_to_long(message)
    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    e = 3
    c = pow(m, e, N)
    return N, e, c


for m in messages:
    N, e, c = RSA_encrypt(m)
    print(f"n = {N}")
    print(f"e = {e}")
    print(f"c = {c}")
```

* Bài này được gửi với số lượng lớn, với mỗi người là một n khác nhau, nhưng e giống nhau và rất nhỏ, ta sẽ áp dụng 
Hastad’s Broadcast Attack
[Twenty Years](https://www.ams.org/notices/199902/boneh.pdf)

* Có n phương trình 
c1 = $m^e$ mod n1
c2 = $m^e$ mod n2
...
cn = $m^e$ mod nn

* Ta sẽ áp dụng định lý thặng dư trung hoa để giải phương trình và tìm ra $m^e$, rồi từ đó tìm được m. Nhưng đề bài cho 7 phương trình, ta chỉ cần chọn ra tối thiểu (và ideal) 3 phương trình đúng để lấy flag, vì có thể đề cho thêm shit để đánh lạc hướng

* Điều kiện để áp dụng là gcd(ni, nj) = 1 với i != j và $m^e$ < n1n2n3 (điều kiện này để khi trả m về không bị cắt mất thông tin và $m^e$ = x, khi đó chỉ việc căn e 2 vế đi để tìm m)

Code:
```
from Crypto.Util.number import long_to_bytes
from itertools import combinations
from sympy.ntheory.modular import crt
from gmpy2 import iroot

cs = [6965891612987861726975066977377253961837139691220763821370036576350605576485706330714192837336331493653283305241193883593410988132245791554283874785871849223291134571366093850082919285063130119121338290718389659761443563666214229749009468327825320914097376664888912663806925746474243439550004354390822079954583102082178617110721589392875875474288168921403550415531707419931040583019529612270482482718035497554779733578411057633524971870399893851589345476307695799567919550426417015815455141863703835142223300228230547255523815097431420381177861163863791690147876158039619438793849367921927840731088518955045807722225, 5109363605089618816120178319361171115590171352048506021650539639521356666986308721062843132905170261025772850941702085683855336653472949146012700116070022531926476625467538166881085235022484711752960666438445574269179358850309578627747024264968893862296953506803423930414569834210215223172069261612934281834174103316403670168299182121939323001232617718327977313659290755318972603958579000300780685344728301503641583806648227416781898538367971983562236770576174308965929275267929379934367736694110684569576575266348020800723535121638175505282145714117112442582416208209171027273743686645470434557028336357172288865172, 5603386396458228314230975500760833991383866638504216400766044200173576179323437058101562931430558738148852367292802918725271632845889728711316688681080762762324367273332764959495900563756768440309595248691744845766607436966468714038018108912467618638117493367675937079141350328486149333053000366933205635396038539236203203489974033629281145427277222568989469994178084357460160310598260365030056631222346691527861696116334946201074529417984624304973747653407317290664224507485684421999527164122395674469650155851869651072847303136621932989550786722041915603539800197077294166881952724017065404825258494318993054344153, 1522280741383024774933280198410525846833410931417064479278161088248621390305797210285777845359812715909342595804742710152832168365433905718629465545306028275498667935929180318276445229415104842407145880223983428713335709038026249381363564625791656631137936935477777236936508600353416079028339774876425198789629900265348122040413865209592074731028757972968635601695468594123523892918747882221891834598896483393711851510479989203644477972694520237262271530260496342247355761992646827057846109181410462131875377404309983072358313960427035348425800940661373272947647516867525052504539561289941374722179778872627956360577, 8752507806125480063647081749506966428026005464325535765874589376572431101816084498482064083887400646438977437273700004934257274516197148448425455243811009944321764771392044345410680448204581679548854193081394891841223548418812679441816502910830861271884276608891963388657558218620911858230760629700918375750796354647493524576614017731938584618983084762612414591830024113057983483156974095503392359946722756364412399187910604029583464521617256125933111786441852765229820406911991809039519015434793656710199153380699319611499255869045311421603167606551250174746275803467549814529124250122560661739949229005127507540805, 23399624135645767243362438536844425089018405258626828336566973656156553220156563508607371562416462491581383453279478716239823054532476006642583363934314982675152824147243749715830794488268846671670287617324522740126594148159945137948643597981681529145611463534109482209520448640622103718682323158039797577387254265854218727476928164074249568031493984825273382959147078839665114417896463735635546290504843957780546550577300001452747760982468547756427137284830133305010038339400230477403836856663883956463830571934657200851598986174177386323915542033293658596818231793744261192870485152396793393026198817787033127061749, 15239683995712538665992887055453717247160229941400011601942125542239446512492703769284448009141905335544729440961349343533346436084176947090230267995060908954209742736573986319254695570265339469489948102562072983996668361864286444602534666284339466797477805372109723178841788198177337648499899079471221924276590042183382182326518312979109378616306364363630519677884849945606288881683625944365927809405420540525867173639222696027472336981838588256771671910217553150588878434061862840893045763456457939944572192848992333115479951110622066173007227047527992906364658618631373790704267650950755276227747600169403361509144]
ns = [14528915758150659907677315938876872514853653132820394367681510019000469589767908107293777996420037715293478868775354645306536953789897501630398061779084810058931494642860729799059325051840331449914529594113593835549493208246333437945551639983056810855435396444978249093419290651847764073607607794045076386643023306458718171574989185213684263628336385268818202054811378810216623440644076846464902798568705083282619513191855087399010760232112434412274701034094429954231366422968991322244343038458681255035356984900384509158858007713047428143658924970374944616430311056440919114824023838380098825914755712289724493770021, 20463913454649855046677206889944639231694511458416906994298079596685813354570085475890888433776403011296145408951323816323011550738170573801417972453504044678801608709931200059967157605416809387753258251914788761202456830940944486915292626560515250805017229876565916349963923702612584484875113691057716315466239062005206014542088484387389725058070917118549621598629964819596412564094627030747720659155558690124005400257685883230881015636066183743516494701900125788836869358634031031172536767950943858472257519195392986989232477630794600444813136409000056443035171453870906346401936687214432176829528484662373633624123, 19402640770593345339726386104915705450969517850985511418263141255686982818547710008822417349818201858549321868878490314025136645036980129976820137486252202687238348587398336652955435182090722844668488842986318211649569593089444781595159045372322540131250208258093613844753021272389255069398553523848975530563989367082896404719544411946864594527708058887475595056033713361893808330341623804367785721774271084389159493974946320359512776328984487126583015777989991635428744050868653379191842998345721260216953918203248167079072442948732000084754225272238189439501737066178901505257566388862947536332343196537495085729147, 12005639978012754274325188681720834222130605634919280945697102906256738419912110187245315232437501890545637047506165123606573171374281507075652554737014979927883759915891863646221205835211640845714836927373844277878562666545230876640830141637371729405545509920889968046268135809999117856968692236742804637929866632908329522087977077849045608566911654234541526643235586433065170392920102840518192803854740398478305598092197183671292154743153130012885747243219372709669879863098708318993844005566984491622761795349455404952285937152423145150066181043576492305166964448141091092142224906843816547235826717179687198833961, 17795451956221451086587651307408104001363221003775928432650752466563818944480119932209305765249625841644339021308118433529490162294175590972336954199870002456682453215153111182451526643055812311071588382409549045943806869173323058059908678022558101041630272658592291327387549001621625757585079662873501990182250368909302040015518454068699267914137675644695523752851229148887052774845777699287718342916530122031495267122700912518207571821367123013164125109174399486158717604851125244356586369921144640969262427220828940652994276084225196272504355264547588369516271460361233556643313911651916709471353368924621122725823, 25252721057733555082592677470459355315816761410478159901637469821096129654501579313856822193168570733800370301193041607236223065376987811309968760580864569059669890823406084313841678888031103461972888346942160731039637326224716901940943571445217827960353637825523862324133203094843228068077462983941899571736153227764822122334838436875488289162659100652956252427378476004164698656662333892963348126931771536472674447932268282205545229907715893139346941832367885319597198474180888087658441880346681594927881517150425610145518942545293750127300041942766820911120196262215703079164895767115681864075574707999253396530263, 19833203629283018227011925157509157967003736370320129764863076831617271290326613531892600790037451229326924414757856123643351635022817441101879725227161178559229328259469472961665857650693413215087493448372860837806619850188734619829580286541292997729705909899738951228555834773273676515143550091710004139734080727392121405772911510746025807070635102249154615454505080376920778703360178295901552323611120184737429513669167641846902598281621408629883487079110172218735807477275590367110861255756289520114719860000347219161944020067099398239199863252349401303744451903546571864062825485984573414652422054433066179558897]
e = 3

pairs = [(c, n) for (n,c) in zip(cs, ns)]
triplet = list(combinations(pairs, 3))

for i in triplet:
    c = [j[0] for j in i]
    n = [j[1] for j in i]
    if crt(c, n):
        x = crt(c, n)[0]
        x = long_to_bytes(iroot(x, 3)[0])
        if b'crypto' in x:
            print(x)
    
```

## Marin's 
> I've found a super fast way to generate primes from my secret list.
> 
> Challenge files:
>   - marin.py
>   - output.txt

marin.py
```
import random
from Crypto.Util.number import bytes_to_long
from secret import secrets, flag


def get_prime(secret):
    prime = 1
    for _ in range(secret):
        prime = prime << 1
    return prime - 1


random.shuffle(secrets)

m = bytes_to_long(flag)
p = get_prime(secrets[0])
q = get_prime(secrets[1])
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
```

* Đề cũng gợi ý ta sẽ dùng các số nguyên tố [Marin Mersenne](https://vi.wikipedia.org/wiki/S%E1%BB%91_nguy%C3%AAn_t%E1%BB%91_Mersenne) có dạng $2^n$ - 1, vì n là số lẻ nên ta sẽ thử phân tích n = 3 * m với m là một số to khủng khiếp, mục đích là chặn đầu trên các số nguyên tố cần dùng

* Sau khi giải phương trình $2^n$ - 1 = m, thì ta sẽ thu được n ~ 4482

Code:
```
from Crypto.Util.number import inverse, long_to_bytes
import random
from Crypto.Util.number import bytes_to_long
import math

lst = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217]

def get_prime(secret):
    prime = 1
    for _ in range(secret):
        prime = prime << 1
    return prime - 1


n = 658416274830184544125027519921443515789888264156074733099244040126213682497714032798116399288176502462829255784525977722903018714434309698108208388664768262754316426220651576623731617882923164117579624827261244506084274371250277849351631679441171018418018498039996472549893150577189302871520311715179730714312181456245097848491669795997289830612988058523968384808822828370900198489249243399165125219244753790779764466236965135793576516193213175061401667388622228362042717054014679032953441034021506856017081062617572351195418505899388715709795992029559042119783423597324707100694064675909238717573058764118893225111602703838080618565401139902143069901117174204252871948846864436771808616432457102844534843857198735242005309073939051433790946726672234643259349535186268571629077937597838801337973092285608744209951533199868228040004432132597073390363357892379997655878857696334892216345070227646749851381208554044940444182864026513709449823489593439017366358869648168238735087593808344484365136284219725233811605331815007424582890821887260682886632543613109252862114326372077785369292570900594814481097443781269562647303671428895764224084402259605109600363098950091998891375812839523613295667253813978434879172781217285652895469194181218343078754501694746598738215243769747956572555989594598180639098344891175879455994652382137038240166358066403475457 
e = 65537
c = 400280463088930432319280359115194977582517363610532464295210669530407870753439127455401384569705425621445943992963380983084917385428631223046908837804126399345875252917090184158440305503817193246288672986488987883177380307377025079266030262650932575205141853413302558460364242355531272967481409414783634558791175827816540767545944534238189079030192843288596934979693517964655661507346729751987928147021620165009965051933278913952899114253301044747587310830419190623282578931589587504555005361571572561916866063458812965314474160499067525067495140150092119620928363007467390920130717521169105167963364154636472055084012592138570354390246779276003156184676298710746583104700516466091034510765027167956117869051938116457370384737440965109619578227422049806566060571831017610877072484262724789571076529586427405780121096546942812322324807145137017942266863534989082115189065560011841150908380937354301243153206428896320576609904361937035263985348984794208198892615898907005955403529470847124269512316191753950203794578656029324506688293446571598506042198219080325747328636232040936761788558421528960279832802127562115852304946867628316502959562274485483867481731149338209009753229463924855930103271197831370982488703456463385914801246828662212622006947380115549529820197355738525329885232170215757585685484402344437894981555179129287164971002033759724456

for i in range(len(lst)):
    for j in range(i+1, len(lst)):
        p = get_prime(lst[i])
        q = get_prime(lst[j])
        if n == p * q:
            phi = (p-1) * (q-1)
            d = inverse(e, phi)
            print(long_to_bytes(pow(c, d, n)))
```

## Ron was wrong, Whit is right
> Here's a bunch of RSA public keys I gathered from people on the net together with messages that they sent.
> 
> As excerpt.py shows, everyone was using PKCS#1 OAEP to encrypt their own messages. It shouldn't be possible to decrypt them, but perhaps there are issues with some of the keys?
> 
> Challenge files:
>   - excerpt.py
>   - keys_and_messages.zip
> 
> Resources:
>   - The recent difficulties with RSA

excert.py
```
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


msg = "???"

with open('21.pem') as f:
    key = RSA.importKey(f.read())

cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(msg)

with open('21.ciphertext', 'w') as f:
    f.write(ciphertext.hex())
```
* Có hẳn một bài báo có tên giống hệt bài [Ron was wrong, Whit is right](https://eprint.iacr.org/2012/064.pdf). Đại loại bài báo nói về việc sử dụng các khóa công khai và phân tích N từ hàng triệu mẫu bằng cách tìm GCD(N1, N2), nếu tìm được thì ta sẽ biết được p, q của từng khóa.

* Ở bài này cho một đống n, e và c, bài này tương đồng với bài **Fast prime** nhưng ta phải thử nhiều hơn.
* Sau khi factor n thì chỉ có file 21 và 34 là phân tích thành 2 số nguyên tố được, và giải file 21 thì sẽ ra được flag

Code:
```
import owiener
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from factordb.factordb import FactorDB
import math

# 21, 34
def cac(lst):
    for i in range(1, 51):

        with open(f'C:\\Users\\ADMIN\\Downloads\\keys_and_messages\\{i}.pem', "rb") as f:
            key = RSA.import_key(f.read())

        N = key.n  # ví dụ RSA modulus
        for num in lst:
            print(i, math.gcd(N, num))

def test(num):
    with open(f'C:\\Users\\ADMIN\\Downloads\\keys_and_messages\\{num}.pem', "rb") as f:
        key = RSA.import_key(f.read())
    f = FactorDB(key.n)
    f.connect()
    factors = f.get_factor_list()
    return factors
a = test(21)
b = test(34)
q1 = a[0]
p1 = a[1]
phi1 = (p1-1)*(q1-1)
e = 65537
d1 = inverse(e, phi1)
n1 = p1 * q1
key = RSA.construct((n1, e, d1))
cipher = PKCS1_OAEP.new(key)
c1 = 'c62d91677825632cb8ac9d2fbee7490fca70b3f067bd8d811fa446a21001de7943cacafc429b2513d3f20c3224d212ca2937a4a4ea10792a1c498b791e978e4b050b525576bc68421e40d9f420c0b8a07778daf69edf2095bf48222896bb2d6581288ce7a2e7aec15a88a440ff1a1e48beb56f68b4f860d1f64a6ec8cafed90846b7d893bc482df69c8478d5a0d6fc2d043cdd97178740a9eb59d2576b5136200c8ea77e648c88e6c5104ca5d0c6add2fc2c8569ce909f8461e7fa3d901fe67eaeff656399d4751fedba9973e246427e0c7a217f5bdc3edcb5033f17b5ef53419e340355a809eb46f48f538e880abd6f72212b02d3dbf2c4f633a503e648d1a835c4574b23e329e1c51078ea7cbb7533e771899498d4a5760bc0799b7e046f268f098fe0b57de47cd70ccf01ad3c9daec5027f306141bfe7a6c0bd29ee6caf94c7433c25e34ee974005e2360337cb6b3cec5eaf5d31d19f01435f4cdcaa455a18e78dee078395b8ad14b9c3a0d817dc1e3109c7b8af35ab3a5950bf47d5e621f9373ef421540052aac307ecea91f9c29c14bfd81b41d4c5a9b34a8ec2fa1ae06c3d881f39286c3d8dbb1849602fecc27bb135f7dd443e2598d247d1182d350b04be1ac0a734cb0e852a36902d88066ac375a35e279b126e413a97aaa35a0ba933f7b8d574c298332ce428c181464b240709a414af1b77103441b6ccfd0790eccea5926844054903c83f4cb415d600a6b7bc771c9e7a86394a2b427ebe8edec08b8095f561827716898e11caf6f0fe562af8a69f7b6469f0e86bdcc32f429f10821c763b34307efc5b2ae7fd524a07e5d0b762c096f025a3f240fb7bd3554582dcce32c175867d93970b0422e17870ec58f2a305545a3d284b3abb2d21a45ad8fd5faed0dc66312a5aa2f994606a51cd6682acd48ea3fb883f0611e1e5c2fb4047b5c80815ba5d3bcfefaf121bfde4d5c91ee27bb899ef0d29fa5c6dc4223ac2bfcff0217d08579a13e9b02dc97aa2622df62eeaaa38bb3bd087cdd209f03e8926a951e90eaa0f678a252a067ac66402a4c85865931689ed3b33f9f6de0c499f140ef508dfba6007a607a271dcbec18a61f7488bba34d143f93bc259310ffbf23f3391734d8d8811a4be8abf6382e55c2ccbfd80b1559d907fd8d46e0431cdbcd8fdb06d57973437f7b8ff5efc5a53c80d552e8fe622971f7376eeea35f4df9b32ada93e531a52b63ba13f6b7bf61ab337d6d93feb0e8c8a309dfa7e5f50e8cf9655b73ae64822b50db5312f35f4718b0668305065ea283ddf8f0a4e8f486ee9d119ebc584be1837b3d959a25ace208ffac2fb703390a72d3027b64fdd1955b513c0403f09232efa1794a277e0be3f4f9f3a6fd23c6e52101e723cef5db7a2a18a107cd522379adb40c5ed36b26cdf53a1000d7d576f1157b42aac3d3ee011275'
c1 = bytes.fromhex(c1)
print(cipher.decrypt(c1))

q2 = b[0]
p2 = b[1]
phi2 = (p2-1)*(q2-1)
e = 65537
d2 = inverse(e, phi2)
n2 = p2 * q2
c2 = '2b9ebee35be06d488a06399b4a3d0b120c9bb08fc420363ce3dde73128f7201a625d724ebc8c31eefaf0aa8d02718a25a68950cadae726c115139755daf67094885a336069f7f1446e6ed145c1c8307833c722a8d36f515cf4e563a8598c51651fe520bd99a8a0f527c9a0e6cd241f9e2876ef953c9d2f82cdca2ac0f235c17a6eebc207b166413f69d4075a770a4db630ed292fc16019c712fcfda0cc52f8b949fc0247eed109f8dd2c9704be0ee1ab57715c36cd644f74dd1aaea47b1b97a418f0426de200a2c37e8a7f6ddc5ba502d27685df0cabe470952a183a3d2a7fb11bb9cf3b3e3d4051a71350be0bf69835cae7d4823f808de9133449e623ebc3173f540155b147fc5a53b7d7eae1f1e52cebd225b934577c26eb2480243d4dba832bee20d845c8df08be49b3867f119de3f80ebd61019bc90104da2c6ad5b9df8f00f0f3f712a988751e98eea0b530f9101721f072b9a3ee9b9fc0ae3d3ad9caeab7c5d68ade9b21a558cd431cdacc7d4146e621618dd542b576da421688aef9f143b491d8bc040fc58ea6a1fe0a4b02995de940f6d9c5ae8860f1ecc2e74d5cbbf6e003533197438eea7d6d619f0c278564f3f98dbe1885028d729abae4962283a019c368ad32d9562efd42eb4d1733a65a3d37d9ad10bed1640a14561d704f0dd52401fb72ede6d6cefe3ea8c2def924c2ad4b006277ef50ac6815b724b53d378a0665275cf9a9a5cd4027561cefe198200de1d5322da69a558e0ded50f7f07be2dbc7dc79f490f08092f6a15ebf06aacbcdbf7840cf7cfd1efd8ba24bcaaa23b4cfbc0d4fa7ad13905c74c30ea50be3dc2ed4fbb354dcb6896decae55a045cec2217150c26477ae2fb7b54960ee4d58dc401ef05965d8044c02ca625c581857254d751ad008e5a7b91476a1c6c8c86ae326d7e484a6fa8c360d6f06be080d4777a128bc21d9077af2186ae47894865802eef4b1567f05787ee26560603b4583c3efcce47663b6eefaad0d13a196cb38e897e701d32000cb31e7aa3737184ce74eb89b3f19b440d6e4c3ffc1140d436e0fd93d878be9e2835e0c2d752de5f07bf806539451ccf3a70c6c2c6e0d1862e68215ccfbe1992bbdd6f516cd41575ad755bd81834c4baaac468e48b42b6428162bc701502610b41817db4794dcf22ada078be59998d22b11c757c3158ab7d647b29a49c4d251877009617a64fa6e7cbd709975d59f44febddad6b63f040ff89fd0da2863dec43432899e634f3d03148cc504938f6bbac48945b942f3d273b03c6a87de9fec1d02f1fcc7e54c123d3157455948c49c98e1a107d9845df18b57c147edd5323cb30c69ef84740cc72ca42af57bf755171430bd060ad1ca73cb2220b3329a31a8636bcb92d791158af13b2531260f19584a521d52fe7a8b3e5eae9308283f8f3ecdf8e24649dbc2011dbff7'
c2 = int(c2, 16)

lst = []
lst.append(q1)
lst.append(q2)
lst.append(p1)
lst.append(p2)

# cac(lst)
```

## RSA Backdoor Viability
```
It seems like my method to generate fast primes was not completely secure. I came up with a new approach to improve security, including a factorization backdoor in case I ever lose my private key. You'll definitely need some complex techniques to break this!

 You may need to tweak the recursion limit (sys.setrecursionlimit(n) in Python) in your programming language to get your solution working.


Challenge files:
  - complex_primes.py
  - output.txt
```

complex_primes.py
```
from Crypto.Util.number import bytes_to_long, getPrime, isPrime

FLAG = b"crypto{????????????????????????????????}"

def get_complex_prime():
    D = 427
    while True:
        s = random.randint(2 ** 1020, 2 ** 1021 - 1)
        tmp = D * s ** 2 + 1
        if tmp % 4 == 0 and isPrime((tmp // 4)):
            return tmp // 4


m = bytes_to_long(FLAG)
p = get_complex_prime()
q = getPrime(2048)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
```

* Có vẻ bài này sẽ phải sử dụng Elliptic Curve để factorize N, nhưng factordb quá mạnh

Code:
```
from Crypto.Util.number import inverse, long_to_bytes

n = 709872443186761582125747585668724501268558458558798673014673483766300964836479167241315660053878650421761726639872089885502004902487471946410918420927682586362111137364814638033425428214041019139158018673749256694555341525164012369589067354955298579131735466795918522816127398340465761406719060284098094643289390016311668316687808837563589124091867773655044913003668590954899705366787080923717270827184222673706856184434629431186284270269532605221507485774898673802583974291853116198037970076073697225047098901414637433392658500670740996008799860530032515716031449787089371403485205810795880416920642186451022374989891611943906891139047764042051071647203057520104267427832746020858026150611650447823314079076243582616371718150121483335889885277291312834083234087660399534665835291621232056473843224515909023120834377664505788329527517932160909013410933312572810208043849529655209420055180680775718614088521014772491776654380478948591063486615023605584483338460667397264724871221133652955371027085804223956104532604113969119716485142424996255737376464834315527822566017923598626634438066724763559943441023574575168924010274261376863202598353430010875182947485101076308406061724505065886990350185188453776162319552566614214624361251463
e = 65537
c = 608484617316138126443275660524263025508135383745665175433229598517433030003704261658172582370543758277685547533834085899541036156595489206369279739210904154716464595657421948607569920498815631503197235702333017824993576326860166652845334617579798536442066184953550975487031721085105757667800838172225947001224495126390587950346822978519677673568121595427827980195332464747031577431925937314209391433407684845797171187006586455012364702160988147108989822392986966689057906884691499234298351003666019957528738094330389775054485731448274595330322976886875528525229337512909952391041280006426003300720547721072725168500104651961970292771382390647751450445892361311332074663895375544959193148114635476827855327421812307562742481487812965210406231507524830889375419045542057858679609265389869332331811218601440373121797461318931976890674336807528107115423915152709265237590358348348716543683900084640921475797266390455366908727400038393697480363793285799860812451995497444221674390372255599514578194487523882038234487872223540513004734039135243849551315065297737535112525440094171393039622992561519170849962891645196111307537341194621689797282496281302297026025131743423205544193536699103338587843100187637572006174858230467771942700918388
p = 20365029276121374486239093637518056591173153560816088704974934225137631026021006278728172263067093375127799517021642683026453941892085549596415559632837140072587743305574479218628388191587060262263170430315761890303990233871576860551166162110565575088243122411840875491614571931769789173216896527668318434571140231043841883246745997474500176671926153616168779152400306313362477888262997093036136582318881633235376026276416829652885223234411339116362732590314731391770942433625992710475394021675572575027445852371400736509772725581130537614203735350104770971283827769016324589620678432160581245381480093375303381611323
q = n // p
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(long_to_bytes(pow(c, d, n)))
```

