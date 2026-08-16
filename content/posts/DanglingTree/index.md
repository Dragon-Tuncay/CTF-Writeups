---
date: 2026-08-16T00:00:00+04:00
draft: false
---

## Introduction

Welcome to my writeup for **Enigma**, a thrilling machine on HackTheBox. This writeup is for educational purposes only. In this walkthrough, we will cover the complete exploitation chain — starting from an open NFS share and email enumeration to gain initial access via an OpenSTAManager RCE (`CVE-2026-38751`). From there, we’ll perform local enumeration, crack database password hashes to pivot users, set up port forwarding with Chisel, and finally leverage a command injection vulnerability in OliveTin (`CVE-2026-27626`) to escalate privileges to root. Let’s dive in!

To begin the assessment, I started with a Nmap scan to identify open ports and services running on the target machine:

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
2049/tcp  open  nfs
43549/tcp open  unknown
43787/tcp open  unknown
53303/tcp open  unknown
54343/tcp open  unknown
57007/tcp open  unknown
```
We notice that port 111 (NFS) is open from the Nmap scan.
```
