# CyberSecBookmarks

A curated collection of web browser bookmarks containing useful Cyber Security tools and services.

N.B. This is a work-in-progress and exists mostly for my personal use. If this is useful to you, please feel free to use it.

## List contents of bookmarks

To extract a list naming each entry in the `bookmarks.html` file, you can download the file and use the following `grep` command:

```bash
grep -Eo '<A [^>]*>([^<]+)</A>|<DT><H3 [^>]*>([^<]+)</H3>' bookmarks.html | sed -E 's/.*>([^<]+)<\/?A?>/\1/; s/.*>([^<]+)<\/H3>/\n\1\n/'
```

This will print a list as shown below:

<h1> Cyber Security Tools </h1>

<h3>Malware Analysis / Reverse Engineering</h3>

<a href="https://REMnux.org">REMnux: A Linux Toolkit for Malware Analysts</a><br>
<a href="https://bazaar.abuse.ch/">MalwareBazaar | Malware sample exchange</a><br>
<a href="https://malshare.com/">MalShare</a><br>
<a href="https://www.virustotal.com/">VirusTotal - Home</a><br>
<a href="https://ssdeep.sourceforge.net/">ssdeep - Fuzzy hashing program</a><br>
<a href="https://any.run/">Interactive Online Malware Analysis Sandbox - ANY.RUN</a><br>
<a href="https://ericzimmerman.github.io/">Eric Zimmerman's tools</a><br>
<a href="https://cve.mitre.org/">CVE - CVE</a><br>
<a href="https://malapi.io/">MalAPI.io</a><br>
<a href="https://www.sans.org/tools/sift-workstation/">SIFT Workstation | SANS Institute</a><br>
<a href="https://unpac.me/">UnpacMe Live Feed</a><br>
<a href="https://virustotal.readme.io/docs/retrohunt">Retrohunt (VirusTotal)</a><br>
<a href="https://www.talosintelligence.com/talos_file_reputation">Talos File Reputation Lookup || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>
<a href="https://www.talosintelligence.com/reputation_center">IP and Domain Intelligence Center || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>


<h3>Vulnerabilities / Exploits</h3>

<a href="https://nvd.nist.gov/">NVD - Search and Statistics</a><br>
<a href="https://www.metadefender.com/">MetaDefender Cloud | Advanced threat prevention and detection</a><br>
<a href="https://talosintelligence.com/">Email and Spam Data || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>
<a href="https://www.trendmicro.com/en_us/business/products/enterprise/endpoint/threat-encyclopedia.html">Threat Encyclopedia | Trend Micro (US)</a><br>
<a href="https://attack.mitre.org/navigator/">ATT&amp;CK® Navigator</a><br>
<a href="https://www.inquest.net/">InQuest Labs - InQuest.net</a><br>
<a href="https://mitre-attack.github.io/attack-navigator/">Analytics (by technique) | MITRE Cyber Analytics Repository</a><br>
<a href="https://stixproject.github.io/stix/">Introduction to STIX</a><br>
<a href="https://taxii.io/">Introduction to TAXII</a><br>


<h3>OSINT</h3>

<a href="https://viewdns.info/">ViewDNS.info - Your one source for DNS related tools!</a><br>
<a href="https://osintframework.com/">OSINT Framework</a><br>
<a href="https://www.osintcurio.us/google-dorks/">Google Dorks – We will always be OSINTCurio.us</a><br>
<a href="https://yandex.com/images/">Yandex Images: search for images</a><br>
<a href="https://bgp.he.net/">Autonomous System Numbers (ASN) &amp; IP Lookup</a><br>
<a href="https://haveibeenpwned.com/">Have I Been Pwned: Check if your email has been compromised in a data breach</a><br>
<a href="https://hunter.io/">Find email addresses in seconds • Hunter (Email Hunter)</a><br>
<a href="https://whois.domaintools.com/">WHOIS Search, Domain Name, Website, and IP Tools - Who.is</a><br>
<a href="https://www.shodan.io/">Shodan Search Engine</a><br>
<a href="https://threatfox.abuse.ch/">ThreatFox | Browse IOCs</a><br>
<a href="https://nerdydata.com/">Search for a list of UA-251372-24 websites - NerdyData</a><br>
<a href="https://github.com/laramies/theHarvester">laramies/theHarvester: E-mails, subdomains and names Harvester - OSINT</a><br>
<a href="https://www.osintcurio.us/reverse-image-search-tips/">Tips and Tricks on Reverse Image Searches – We will always be OSINTCurio.us</a><br>
<a href="https://www.bing.com/images/">Bing Image Inspiration Feed</a><br>
<a href="https://ffmpeg.org/">FFmpeg</a><br>
<a href="https://osintvm.com/">OSINT VM</a><br>
<a href="https://cirw.in/gpg-decoder/">https://cirw.in/gpg-decoder/</a><br>
<a href="https://hunter.io/">Email Finder: Free email search by name • Hunter</a><br>
<a href="https://archive.org/web/">Internet Archive: Wayback Machine</a><br>
<a href="https://crt.sh/">crt.sh | Certificate Search</a><br>
<a href="https://entrust.com/">Entrust Certificate Search - Entrust, Inc.</a><br>
<a href="https://urlscan.io/">URL and website scanner - urlscan.io</a><br>
<a href="https://ipinfo.io/">Trusted IP Data Provider, from IPv6 to IPv4 - IPinfo.io</a><br>
<a href="https://wannabrowser.com/">Wannabrowser</a><br>
<a href="https://www.browserling.com/">Browserling – Online cross-browser testing</a><br>
<a href="https://www.arin.net/">Requesting IP Addresses or ASNs - American Registry for Internet Numbers</a><br>

<h3>Hashing / Encryption</h3>

<a href="https://www.base64decode.org/">Base64 Decode and Encode - Online</a><br>
<a href="https://binaryfuck.com/">Binaryfuck Language - Online Decoder, Encoder, Translator</a><br>
<a href="https://tio.run/#brainfuck">Online Brainfuck Decoder</a><br>
<a href="https://www.appdevtools.com/base64/">Base64 Encoder / Decoder Online - AppDevTools</a><br>
<a href="https://gchq.github.io/CyberChef/">CyberChef</a><br>
<a href="https://hashes.com/en/tools/hash_calculator">Hash decoder and calculator</a><br>
<a href="https://www.rapidtables.com/calc/math/hex-calculator.html">Hex Calculator</a><br>
sha512: b6a233fb9b2d8772b636ab581169b58c98bd4b8df25e452911ef7556<br>
<a href="https://crackstation.net/">CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.</a><br>
<a href="https://hashkiller.io/">Hashkiller.io - List Manager</a><br>
<a href="https://www.urldecoder.org/">URL Decode and Encode - Online</a><br>
<a href="https://www.devglan.com/online-tools/des-encryption-decryption">DES Encryption / Decryption Tool</a><br>
<a href="https://www.md5hashgenerator.com/">Encrypt and Decrypt your MD5 hashes online</a><br>
<a href="https://www.md5online.org/">MD5 Online | Free MD5 Decryption, MD5 Hash Decoder</a><br>
<a href="https://hashcat.net/hashcat/">hashcat - advanced password recovery</a><br>
<a href="https://quipqiup.com/">quipqiup - cryptoquip and cryptogram solver</a><br>

<h3>Reconnaissance</h3>

<a href="https://www.wappalyzer.com/">Find out what websites are built with - Wappalyzer</a><br>
<a href="https://builtwith.com/">BuiltWith Technology Lookup</a><br>
<a href="https://www.whitepages.com/">People Finder - People Search, Background Checks & Phone Number Lookup</a><br>

<h3>Network / DNS Tools</h3>

<a href="https://mxtoolbox.com/MXLookup.aspx">MX Lookup Tool - Check your DNS MX Records online - MxToolbox</a><br>
<a href="https://shodan.io/developer">Shodan Developer</a><br>
<a href="https://nmap.org/book/nmap-cheatsheet.html">Nmap Cheat Sheet 2024: All the Commands & Flags</a><br>
<a href="https://wigle.net/">WiGLE: Wireless Network Mapping</a><br>

<h3>Phishing / Social Engineering</h3>

<a href="https://gophish.io/">Gophish - Open Source Phishing Framework</a><br>
<a href="https://github.com/trustedsec/social-engineer-toolkit">TrustedSec | The Social Engineering Toolkit (SET)</a><br>
<a href="https://www.trustedsec.com/2020/09/intro-to-macros-and-vba-for-script-kiddies/">TrustedSec | Intro to Macros and VBA for Script Kiddies</a><br>

<h3>Linux / Privilege Escalation</h3>

<a href="https://gtfobins.github.io/">GTFOBins</a><br>

<h3>GitHub Repos</h3>

<a href="https://github.com/rebootuser/LinEnum">GitHub - rebootuser/LinEnum: Scripted Local Linux Enumeration & Privilege Escalation Checks</a><br>
<a href="https://github.com/The-Z-Labs/linux-exploit-suggester">GitHub - The-Z-Labs/linux-exploit-suggester: Linux privilege escalation auditing tool</a><br>
<a href="https://github.com/diego-treitos/linux-smart-enumeration">GitHub - diego-treitos/linux-smart-enumeration: Linux enumeration tool for pentesting and CTFs with verbosity levels</a><br>
<a href="https://github.com/linted/linuxprivchecker">GitHub - linted/linuxprivchecker: linuxprivchecker.py -- a Linux Privilege Escalation Check Script</a><br>
<a href="https://github.com/aboul3la/Sublist3r">GitHub - aboul3la/Sublist3r: Fast subdomains enumeration tool for penetration testers</a><br>
<a href="https://github.com/mandatoryprogrammer/xsshunter-express">GitHub - mandatoryprogrammer/xsshunter-express: An easy-to-setup version of XSS Hunter. Sets up in five minutes and requires no maintenance!</a><br>
<a href="https://github.com/payloadbox/command-injection-payload-list">GitHub - payloadbox/command-injection-payload-list: 🎯 Command Injection Payload List</a><br>
<a href="https://github.com/gtworek/Priv2Admin">GitHub - gtworek/Priv2Admin: Exploitation paths allowing you to (mis)use the Windows Privileges to elevate your rights within the OS.</a><br>
<a href="https://github.com/itm4n/PrivescCheck">GitHub - itm4n/PrivescCheck: Privilege Escalation Enumeration Script for Windows</a><br>
<a href="https://github.com/bitsadmin/wesng">GitHub - bitsadmin/wesng: Windows Exploit Suggester - Next Generation</a><br>
<a href="https://github.com/peass-ng/PEASS-ng">PEASS-ng/linPEAS at master · peass-ng/PEASS-ng · GitHub</a><br>
<a href="https://github.com/jamf/PPPC-Utility">GitHub - jamf/PPPC-Utility: Privacy Preferences Policy Control (PPPC) Utility</a><br>
<a href="https://github.com/lgandx/Responder">GitHub - lgandx/Responder: Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.</a><br>
<a href="https://github.com/GhostPack/Seatbelt">GitHub - GhostPack/Seatbelt: Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.</a><br>
<a href="https://github.com/klsecservices/rpivot">klsecservices/rpivot: socks4 reverse proxy for penetration testing</a><br>
<a href="https://github.com/jpillora/chisel">jpillora/chisel: A fast TCP/UDP tunnel over HTTP</a><br>
<a href="https://github.com/AJChestnut/Network-Services-TryHackMe-Writeup">AJChestnut/Network-Services-TryHackMe-Writeup: This is a writeup for the TryHackMe.com room, Network Services, created by Polomints.</a><br>
<a href="https://github.com/NationalSecurityAgency/ghidra/releases">Releases · NationalSecurityAgency/ghidra</a><br>
<a href="https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1">PowerSploit/Exfiltration/Get-GPPPassword.ps1 at master · PowerShellMafia/PowerSploit</a><br>
<a href="https://github.com/SnaffCon/Snaffler">SnaffCon/Snaffler: a tool for pentesters to help find delicious candy, by @l0ss and @Sh3r4 (Twitter: @/mikeloss and @/sh3r4_hax)</a><br>
<a href="https://github.com/alexjercan/alexjercan.github.io">alexjercan/alexjercan.github.io: Join the Gang Gang and have the latest AI and Tech content.</a><br>
<a href="https://github.com/cotes2020/jekyll-theme-chirpy">cotes2020/jekyll-theme-chirpy: A minimal, responsive, and feature-rich Jekyll theme for technical writing.</a><br>
<a href="https://github.com/danielmiessler/SecLists">GitHub - danielmiessler/SecLists: SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.</a><br>
<a href="https://github.com/fortra/impacket">fortra/impacket: Impacket is a collection of Python classes for working with network protocols.</a><br>
<a href="https://github.com/jesusgavancho/TryHackMe_and_HackTheBox/blob/master/Credentials%20Harvesting.md">TryHackMe_and_HackTheBox/Credentials Harvesting.md at master · jesusgavancho/TryHackMe_and_HackTheBox</a><br>
<a href="https://github.com/leoloobeek/LAPSToolkit">leoloobeek/LAPSToolkit: Tool to audit and attack LAPS environments</a><br>
<a href="https://github.com/radareorg/radare2">radareorg/radare2: UNIX-like reverse engineering framework and command-line toolset</a><br>
<a href="https://github.com/samratashok/nishang">nishang/Gather at master · samratashok/nishang</a><br>
<a href="https://github.com/sshuttle/sshuttle">sshuttle</a><br>

<h3>Persistence</h3>

<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md">PayloadsAllTheThings/Methodology and Resources/Windows - Persistence.md at master · swisskyrepo/PayloadsAllTheThings · GitHub</a><br>
<a href="https://oddvarmoe.com/persistence-using-runonceex-hidden-from-autoruns-exe/">Persistence using RunOnceEx – Hidden from Autoruns.exe – Oddvar Moe's Blog</a><br>
<a href="https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1">Establishing Registry Persistence via SQL Server with PowerUpSQL</a><br>
<a href="https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx">webshell/fuzzdb-webshell/asp/cmdasp.aspx at master · tennc/webshell · GitHub</a><br>

<h3>Cheatsheets</h3>

<a href="https://medium.com/@richsn/win-reverse-shells-cheatsheet-b73f687e0660">Windows Reverse Shells Cheatsheet | by Rich | Medium</a><br>
<a href="https://github.com/samratashok/nishang/blob/master/Windows-Reverse-Shells-CheatSheet.md">Windows Reverse Shells Cheatsheet</a><br>
<a href="https://devhints.io/bash">Bash scripting cheatsheet</a><br>
<a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">Password Storage - OWASP Cheat Sheet Series</a><br>
<a href="https://www.exploit-db.com/">Exploit Database - Exploits for Penetration Testers, Researchers, and Ethical Hackers</a><br>
<a href="https://docs.pwntools.com/en/stable/">pwntools — pwntools 4.12.0 documentation</a><br>

<h3>Miscellaneous Tools</h3>

<a href="https://geoguessr.com/">GeoGuessr - Let's explore the world!</a><br>
<a href="https://imageresizer.com/">Image Resizer</a><br>
<a href="https://regexr.com/">RegExr: Learn, Build, & Test RegEx</a><br>
<a href="https://live.sysinternals.com/">live.sysinternals.com - /</a><br>
<a href="https://www.onlinegdb.com/online_c_compiler">GDB online Debugger | Compiler - Code, Compile, Run, Debug online C, C++</a><br>
<a href="https://vectr.com/">Features | VECTR</a><br>
<a href="https://cheatengine.org/">Cheat Engine</a><br>
<a href="https://www.openstack.org/">Open Source Cloud Computing Infrastructure - OpenStack</a><br>
<a href="https://www.srihash.org/">SRI Hash Generator</a><br>
<a href="https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php">php-reverse-shell.php</a><br>

<h3>Crypto & Blockchain</h3>

<a href="https://remix.ethereum.org/">Remix - Ethereum IDE</a><br>
<a href="https://etherscan.io/address/0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef">Address 0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef | Etherscan</a><br>

<h3>[unsorted]</h3>

<a href="https://www.splunk.com/en_us/resources/what-is-password-hashing.html">Splunk Password Hashing - sha512crypt ($6$) SHA512 (Unix)</a><br>
<a href="https://pentestmonkey.net/tools/reverse-shell-cheat-sheet">Reverse Shell Cheat Sheet | pentestmonkey</a><br>
<a href="https://user-agents.org/">User Agents</a><br>
<a href="https://secwiki.org/w/Cheatsheet:Spawning_a_TTY_Shell">Spawning a TTY Shell | SecWiki</a><br>
<a href="https://www.emlviewer.com/">Free MSG EML Viewer | Free Online Email Viewer</a><br>
<a href="https://pinvoke.net/">pinvoke.net: the interop wiki!</a><br>
<a href="https://lolbas-project.github.io/lolbas/commands/certutil/">Certutil | LOLBAS</a><br>
<a href="https://snyk.io/plans/">Plans and pricing | For teams of all sizes | Snyk</a><br>
<a href="https://aikido.io/">Aikido — AppSec Platform For Code & Cloud Security</a><br>
<a href="https://github.com/DidierStevens/oletools/blob/master/oledump.py">oledump.py | Didier Stevens</a><br>

