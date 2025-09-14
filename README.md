# SiFT (Simple File Transfer) v1.0 Implementation

This repository contains a Python implementation of the Simple File Transfer (SiFT) protocol, version 1.0. SiFT is a secure protocol for clients to execute remote file commands on a server over a TCP/IP network.

## About the SiFT Protocol

SiFT v1.0 is designed to be a secure file transfer protocol that operates over insecure networks. It provides protection against eavesdropping, message modification, deletion, and replay attacks by using a cryptographically secured message transfer sub-protocol (MTP).

The protocol uses a login system to authenticate clients and establish shared secret keys for secure communication.

## Key Features

- **Secure Communication**: All messages are encrypted and authenticated using AES in GCM mode.
- **User Authentication**: Clients authenticate with a username and password.
- **Command-Based**: Supports 7 essential file system commands:
    - `pwd`: Print current working directory.
    - `lst`: List content of the current directory.
    - `chd`: Change directory.
    - `mkd`: Make a new directory.
    - `del`: Delete a file or directory.
    - `upl`: Upload a file to the server.
    - `dnl`: Download a file from the server.
- **Structured Sub-Protocols**: Consists of several sub-protocols for handling login, commands, uploads, and downloads, all built on top of a secure Message Transfer Protocol (MTP).

## Files in this Repository

- `SiFT v1.0 specification.md`: The official specification document for the SiFT v1.0 protocol.
- `server.py`: The SiFT server application.
- `client.py`: The SiFT client application.
- `siftcmd.py`, `siftdnl.py`, `siftlogin.py`, `siftmtp.py`, `siftupl.py`: Python modules likely containing the implementation for the different SiFT sub-protocols (Commands, Download, Login, MTP, Upload).
- `users.txt`: A file likely used by the server to manage user credentials.
- `public.pem`, `private.pem`: RSA key pair for the server to secure the initial key exchange.
- `test_1.txt`, `test_2.txt`: Sample files for testing uploads and downloads.
- `users/`: A directory containing user-specific files and folders, representing the server's file system for different users.

## How to Run

(Note: These are general instructions based on the file structure. You may need to install dependencies like `pycryptodome`.)

### 1. Start the Server

Open a terminal and run the server:
```bash
python3 server.py
```
The server will start listening for client connections on TCP port 5150.

### 2. Run the Client

Open another terminal and run the client:
```bash
python3 client.py
```
The client will prompt you for a username and password to log in to the server. Once logged in, you can use the supported SiFT commands.
