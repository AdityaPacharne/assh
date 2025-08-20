# assh — It's SSH, but ASSh

`assh` is an implementation of SSH...  
but it's **less secure** and **blazingly fast** due to no additional features :)

But hey, I'm proud of it.

Just a final year student messing around with cryptography and sockets, trying to understand how SSH works from scratch.

---

## What it does
- **asshd** (server) listens on port 14641 for incoming TCP connections
- **assh** (client) connects to server using IP address
- Does a janky but working **Diffie-Hellman key exchange** to establish shared secret
- Uses **AES-CTR** for symmetric encryption of all commands
- Uses **SHA256** for hashing stuff
- Uses **LibTomMath** for big integer math (DH calculations)
- Server executes commands and sends encrypted output back

---

## What's missing (aka why it's not actually SSH)
- No host key verification
- No user authentication  
- No PTY support (so no vim😞)
- Single connection only
- Probably has security holes I don't know about

---

## Why I did this🙃
Wanted to understand how SSH works by building it from scratch.  
Figured implementing the crypto myself would teach me more than just using existing libraries.

---

## How to build

Requirements:  
1. A C++ compiler
2. make

Clone this repository and run make
```bash
git clone https://github.com/AdityaPacharne/assh.git
cd assh 
make
```

---

## How to check if this thing works

First you would have to run the server executable or the client side wont be able to connect.  
If you are on a **Server** run
```bash
./asshd
```
or
If you are **Client** run ./assh along with server ip
```bash
./assh 127.0.0.1
```

---

## Demonstration Video
https://github.com/user-attachments/assets/92228f77-c804-47c9-a45c-bc9ded515221

---

## Stuff I didn’t write

### AES (Brian Gladman)
I’m using [Brian Gladman’s AES implementation](https://github.com/BrianGladman/aes) in CTR mode.  
You can find it in `crypto/aes/`

### SHA256 (Zedwood)
For SHA256, I used [Zedwood's single-file SHA256 implementation](http://www.zedwood.com/article/cpp-sha256-function).  
You can find it at `crypto/hashing/sha256.cpp`

### Big Ints (LibTomMath)
Used [LibTomMath](https://github.com/libtom/libtommath) for doing big int math.  
It’s public domain and handles all the modular exponentiation stuff in DH

---

## License

All the third-party code is public domain or BSD, and credit is given above.  
My own code? Feel free to read, use or laugh at it.

---

