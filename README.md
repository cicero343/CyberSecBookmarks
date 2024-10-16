# CyberSecBookmarks

A curated collection of web browser bookmarks containing useful Cyber Security tools and services.

N.B. This is a work-in-progress and exists mostly for my personal use. If this is useful to you, please feel free to use it.

## List contents of bookmarks

To extract a list naming each entry in the `bookmarks.html` file, you can download the file and use the following `grep` command:

```bash
grep -Eo '<A [^>]*>([^<]+)</A>|<DT><H3 [^>]*>([^<]+)</H3>' bookmarks.html | sed -E 's/.*>([^<]+)<\/?A?>/\1/; s/.*>([^<]+)<\/H3>/\n\1\n/'
```

This will print a list as shown below:

<h3> Cyber Security Tools <h3>

Malware Analysis / Reverse Engineering

    <a href="https://REMnux.org">REMnux: A Linux Toolkit for Malware Analysts</a>
    <a href="https://malwarebazaar.eu/">MalwareBazaar | Malware sample exchange</a>
    <a href="https://malshare.com/">MalShare</a>
    <a href="https://www.virustotal.com/">VirusTotal - Home</a>
    <a href="https://ssdeep.sourceforge.net/">ssdeep - Fuzzy hashing program</a>
    <a href="https://any.run/">Interactive Online Malware Analysis Sandbox - ANY.RUN</a>
    <a href="https://ericzimmerman.github.io/">Eric Zimmerman's tools</a>
    <a href="https://cve.mitre.org/">CVE - CVE</a>
    <a href="https://malapi.io/">MalAPI.io</a>
    <a href="https://sift.wireghoul.com/">SIFT Workstation | SANS Institute</a>
    <a href="https://unpac.me/">UnpacMe Live Feed</a>
    <a href="https://retrohunt.com/">Retrohunt</a>
    <a href="https://talosintelligence.com/">Talos File Reputation Lookup || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a>
    <a href="https://talosintelligence.com/">IP and Domain Intelligence Center || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a>

Vulnerabilities / Exploits

    NVD - Search and Statistics
    MetaDefender Cloud | Advanced threat prevention and detection
    Email and Spam Data || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence
    Threat Encyclopedia | Trend Micro (US)
    ATT&CK® Navigator
    InQuest Labs - InQuest.net
    Analytics (by technique) | MITRE Cyber Analytics Repository
    Introduction to STIX
    Introduction to TAXII

OSINT

    ViewDNS.info - Your one source for DNS related tools!
    OSINT Framework
    Google Dorks – We will always be OSINTCurio.us
    Yandex Images: search for images
    Autonomous System Numbers (ASN) & IP Lookup
    Have I Been Pwned: Check if your email has been compromised in a data breach
    Find email addresses in seconds • Hunter (Email Hunter)
    WHOIS Search, Domain Name, Website, and IP Tools - Who.is
    Shodan Search Engine
    ThreatFox | Browse IOCs
    Search for a list of UA-251372-24 websites - NerdyData
    laramies/theHarvester: E-mails, subdomains and names Harvester - OSINT
    Tips and Tricks on Reverse Image Searches – We will always be OSINTCurio.us
    Bing Image Inspiration Feed
    FFmpeg
    OSINT VM
    https://cirw.in/gpg-decoder/
    Email Finder: Free email search by name • Hunter
    Internet Archive: Wayback Machine
    crt.sh | Certificate Search
    Entrust Certificate Search - Entrust, Inc.
    URL and website scanner - urlscan.io
    Trusted IP Data Provider, from IPv6 to IPv4 - IPinfo.io
    Wannabrowser
    Browserling – Online cross-browser testing
    Requesting IP Addresses or ASNs - American Registry for Internet Numbers

Hashing / Encryption

    Base64 Decode and Encode - Online
    Binaryfuck Language - Online Decoder, Encoder, Translator
    Online Brainfuck Decoder
    Base64 Encoder / Decoder Online - AppDevTools
    CyberChef
    Hash decoder and calculator
    Hex Calculator
    sha512: b6a233fb9b2d8772b636ab581169b58c98bd4b8df25e452911ef7556
    CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.
    Hashkiller.io - List Manager
    URL Decode and Encode - Online
    DES Encryption / Decryption Tool
    Encrypt and Decrypt your MD5 hashes online
    MD5 Online | Free MD5 Decryption, MD5 Hash Decoder
    hashcat - advanced password recovery
    quipqiup - cryptoquip and cryptogram solver

Reconnaissance

    Find out what websites are built with - Wappalyzer
    BuiltWith Technology Lookup
    People Finder - People Search, Background Checks & Phone Number Lookup

Network / DNS Tools

    MX Lookup Tool - Check your DNS MX Records online - MxToolbox
    Shodan Developer
    Nmap Cheat Sheet 2024: All the Commands & Flags
    WiGLE: Wireless Network Mapping

Phishing / Social Engineering

    Gophish - Open Source Phishing Framework
    TrustedSec | The Social Engineering Toolkit (SET)
    TrustedSec | Intro to Macros and VBA for Script Kiddies

Linux / Privilege Escalation

    GTFOBins

GitHub Repos

    GitHub - rebootuser/LinEnum: Scripted Local Linux Enumeration & Privilege Escalation Checks
    GitHub - The-Z-Labs/linux-exploit-suggester: Linux privilege escalation auditing tool
    GitHub - diego-treitos/linux-smart-enumeration: Linux enumeration tool for pentesting and CTFs with verbosity levels
    GitHub - linted/linuxprivchecker: linuxprivchecker.py -- a Linux Privilege Escalation Check Script
    GitHub - aboul3la/Sublist3r: Fast subdomains enumeration tool for penetration testers
    GitHub - mandatoryprogrammer/xsshunter-express: An easy-to-setup version of XSS Hunter. Sets up in five minutes and requires no maintenance!
    GitHub - payloadbox/command-injection-payload-list: 🎯 Command Injection Payload List
    GitHub - gtworek/Priv2Admin: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.
    GitHub - itm4n/PrivescCheck: Privilege Escalation Enumeration Script for Windows
    GitHub - bitsadmin/wesng: Windows Exploit Suggester - Next Generation
    GitHub - peass-ng/linPEAS: PEASS-ng
    GitHub - jamf/PPPC-Utility: Privacy Preferences Policy Control (PPPC) Utility
    GitHub - lgandx/Responder: Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
    GitHub - GhostPack/Seatbelt: Seatbelt is a C# project that performs a number of security-oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
    GitHub - klsecservices/rpivot: Socks4 reverse proxy for penetration testing
    GitHub - jpillora/chisel: A fast TCP/UDP tunnel over HTTP
    GitHub - AJChestnut/Network-Services-TryHackMe-Writeup: This is a writeup for the TryHackMe.com room, Network Services, created by Polomints.
    GitHub - NationalSecurityAgency/ghidra: Ghidra
    GitHub - PowerShellMafia/PowerSploit: PowerSploit
    GitHub - SnaffCon/Snaffler: A tool for pentesters to help find delicious candy, by @l0ss and @Sh3r4 (Twitter: @/mikeloss and @/sh3r4_hax)
    GitHub - alexjercan/alexjercan.github.io: Join the Gang Gang and have the latest AI and Tech content.
    GitHub - cotes2020/jekyll-theme-chirpy: A minimal, responsive, and feature-rich Jekyll theme for technical writing.
    GitHub - danielmiessler/SecLists: SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place.
