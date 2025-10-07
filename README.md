# 🕸️ BEWS — *Barely Effective Web Server*

A **very minimalist web server** written in C — for fun, learning, and a little nostalgia!  
Because who *doesn't* like reinventing the wheel (poorly, but proudly)? 😎

---

## ⚙️ 0. Installation

```bash
$ git clone git://github.com/z3count/bews
$ cd bews
$ make
```
Then, with root privileges:

```bash
$ sudo make install
```

## 🚀 1. Usage
Run the web server on port 80, serving files from /usr/local/var/www:

```bash
$ bews
```
If you’re not running as root, you can change the port and root directory
(to share “useful” stuff with your friends 🤫):

```bash
$ bews -p 1337 -r ~/Dumb.and.Dumber
```
Run as a daemon:

```bash
$ bews -d
```

For all available options:

```bash
$ bews -h
```

## 🧩 2. (Lack of) Features
Features:

🫠 None, of course — this project is for fun and learning!

Known issues:

- Only supports basic GET requests
- Directory traversal? Probably.
- Memory safety? Who knows!
- The list is way too long... 😅

## 🔧 3. Uninstall
With root privileges, from the bews source directory:

```bash
$ sudo make uninstall
```

## 🐛 4. Issues & Feedback

Found a bug? Got ideas? Just bored?
Open an issue or drop a comment on GitHub:

👉 https://github.com/z3count/bews/issues

## 💡 Author’s note

BEWS was never meant to be secure, fast, or even good.
It’s just a playground for C hackers who enjoy poking at sockets and pretending it’s still 1998.

Enjoy responsibly. 🍻
