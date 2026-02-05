# CyberSecBookmarks

A curated collection of web browser bookmarks containing useful Cyber Security tools and services.

N.B. This is a work-in-progress and exists mostly for my personal use. If this is useful to you, please feel free to use it.

## List contents of bookmarks

If you only want to extract the **URLs** of each entry in the `bookmarks.html` file, you can download the file and use one of the following commands:

### Bash (URLs grouped by folder)

```bash
awk '/<DT><H3 /{l=$0;sub(/.*<DT><H3 [^>]*>/,"",l);sub(/<\/H3>.*/,"",l);printf "\n## %s\n\n",l}
     /<A [^>]*HREF="/{l=$0;sub(/.*HREF="/,"",l);sub(/".*/,"",l);print "- "l}' bookmarks.html
```

---

### PowerShell (URLs grouped by folder)

```powershell
Get-Content bookmarks.html | ForEach-Object {
    if ($_ -match '<DT><H3 [^>]*>([^<]+)</H3>') { "`n[$($matches[1])]`n" }
    elseif ($_ -match '<A [^>]*HREF="([^"]+)"') { $matches[1] }
}
```

OR

To extract a list naming each entry in the `bookmarks.html` file, use one of the following commands:

Bash:
```bash
grep -Eo '<A [^>]*>([^<]+)</A>|<DT><H3 [^>]*>([^<]+)</H3>' bookmarks.html | sed -E 's/.*>([^<]+)<\/?A?>/\1/; s/.*>([^<]+)<\/H3>/\n\1\n/'
```

PowerShell:
```powershell
Get-Content bookmarks.html | Select-String -Pattern '<A [^>]*>([^<]+)</A>|<DT><H3 [^>]*>([^<]+)</H3>' | ForEach-Object { if ($_ -match '<A [^>]*>([^<]+)</A>') { $matches[1] } elseif ($_ -match '<DT><H3 [^>]*>([^<]+)</H3>') { "`n$($matches[1])`n" } }
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
<a href="https://www.cve.org/">CVE Website</a><br>
<a href="https://malapi.io/">MalAPI.io</a><br>
<a href="https://www.sans.org/tools/sift-workstation/">SIFT Workstation | SANS Institute</a><br>
<a href="https://unpac.me/">UnpacMe Live Feed</a><br>
<a href="https://virustotal.readme.io/docs/retrohunt">Retrohunt (VirusTotal)</a><br>
<a href="https://www.talosintelligence.com/talos_file_reputation">Talos File Reputation Lookup || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>
<a href="https://www.hybrid-analysis.com/">Free Automated Malware Analysis Service - powered by Falcon Sandbox</a><br>
<a href="https://www.phishtool.com/">PhishTool</a><br>
<a href="https://tria.ge/login?return_to=%2Fsubmit">Triage | Triage</a><br>
<a href="https://www.encryptomatic.com/viewer/">Free MSG EML Viewer | Free Online Email Viewer</a><br>

<h3>Vulnerabilities / Exploits</h3>

<a href="https://nvd.nist.gov/">NVD - Search and Statistics</a><br>
<a href="https://www.metadefender.com/">MetaDefender Cloud | Advanced threat prevention and detection</a><br>
<a href="https://attack.mitre.org/navigator/">ATT&amp;CK® Navigator</a><br>
<a href="https://www.exploit-db.com/">Exploit Database - Exploits for Penetration Testers, Researchers, and Ethical Hackers</a><br>
<a href="https://www.zaproxy.org/">ZAP</a><br>
<a href="https://www.cvedetails.com/">CVE security vulnerability database. Security vulnerabilities, exploits, references and more</a><br>
<a href="https://d3fend.mitre.org/">D3FEND Matrix | MITRE D3FEND™</a><br>
<a href="https://engage.mitre.org/matrix/">Matrix | MITRE Engage™</a><br>
<a href="https://valhalla.nextron-systems.com/">Valhalla YARA Rules - Valhalla</a><br>
<a href="https://mandiant.github.io/capa/explorer/#/">capa Explorer Web</a><br>
<a href="https://www.nextron-systems.com/thor-lite/">THOR Lite: Free Multi-Platform IOC and YARA Scanner - Nextron Systems</a><br>
<a href="https://securityheaders.com/">Analyse your HTTP response headers</a><br>

<h3>Threat Intelligence</h3>

<a href="https://search.censys.io/">Censys Search</a><br>
<a href="https://socradar.io/labs/">SOCRadar LABS</a><br>
<a href="https://exchange.xforce.ibmcloud.com/">IBM X-Force Exchange</a><br>
<a href="https://abuse.ch/#platforms">abuse.ch | Fighting malware and botnets</a><br>
<a href="https://threatfox.abuse.ch/browse/">ThreatFox | Browse IOCs</a><br>
<a href="https://oasis-open.github.io/cti-documentation/stix/intro#whats-new-in-stix-21">Introduction to STIX</a><br>
<a href="https://oasis-open.github.io/cti-documentation/taxii/intro">Introduction to TAXII</a><br>
<a href="https://car.mitre.org/analytics/by_technique">Analytics (by technique) | MITRE Cyber Analytics Repository</a><br>
<a href="https://labs.inquest.net/">InQuest Labs - InQuest.net</a><br>
<a href="https://www.trendmicro.com/vinfo/us/threat-encyclopedia">Threat Encyclopedia | Trend Micro (US)</a><br>
<a href="https://talosintelligence.com/reputation_center/email_rep">Email and Spam Data || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>
<a href="https://cybermap.kaspersky.com/">Kaspersky Cyberthreat Live Map</a><br>


<h3>OSINT</h3>

<a href="https://osintframework.com/">OSINT Framework</a><br>
<a href="https://www.osintcurio.us/2019/12/20/google-dorks/">Google Dorks – We will always be OSINTCurio.us</a><br>
<a href="https://yandex.com/images/">Yandex Images: search for images</a><br>
<a href="https://asnlookup.com/">Autonomous System Numbers (ASN) &amp; IP Lookup</a><br>
<a href="https://haveibeenpwned.com/">Have I Been Pwned: Check if your email has been compromised in a data breach</a><br>
<a href="https://who.is/">WHOIS Search, Domain Name, Website, and IP Tools - Who.is</a><br>
<a href="https://www.shodan.io/">Shodan Search Engine</a><br>
<a href="https://www.shodan.io/search/examples">Shodan Query Examples</a><br>
<a href="https://www.nerdydata.com/reports/new?search={%22all%22:[{%22type%22:%22code%22,%22value%22:%22UA-251372-24%22}],%22any%22:[],%22none%22:[]}">Search for a list of UA-251372-24 websites - NerdyData</a><br>
<a href="https://github.com/laramies/theHarvester">laramies/theHarvester: E-mails, subdomains and names Harvester - OSINT</a><br>
<a href="https://www.osintcurio.us/2020/04/12/tips-and-tricks-on-reverse-image-searches/">Tips and Tricks on Reverse Image Searches – We will always be OSINTCurio.us</a><br>
<a href="https://www.bing.com/images/feed">Bing Image Inspiration Feed</a><br>
<a href="https://www.tracelabs.org/initiatives/osint-vm">OSINT VM</a><br>
<a href="https://cirw.in/gpg-decoder/">https://cirw.in/gpg-decoder/</a><br>
<a href="https://hunter.io/email-finder">Email Finder: Free email search by name • Hunter</a><br>
<a href="https://archive.org/web/">Internet Archive: Wayback Machine</a><br>
<a href="https://crt.sh/">crt.sh | Certificate Search</a><br>
<a href="https://ui.ctsearch.entrust.com/ui/ctsearchui">Entrust Certificate Search - Entrust, Inc.</a><br>
<a href="https://urlscan.io/">URL and website scanner - urlscan.io</a><br>
<a href="https://ipinfo.io/">Trusted IP Data Provider, from IPv6 to IPv4 - IPinfo.io</a><br>
<a href="https://www.wannabrowser.net/">Wannabrowser</a><br>
<a href="https://www.browserling.com/">Browserling – Online cross-browser testing</a><br>
<a href="https://cybernews.com/personal-data-leak-check/">Personal Data Leak Checker: Your Email & Data - Breached? | CyberNews</a><br>
<a href="https://idprotect.trendmicro.com/en-us/leakchecker?utm_source=helpcenter&utm_medium=referral">Data Leak Checker | Trend Micro ID Protection</a><br>
<a href="https://tineye.com/">TinEye - Reverse Image Search and Recognition</a><br>
<a href="https://browserleaks.com/">Browserleaks - Check your browser for privacy leaks</a><br>

<h3>Hashing / Encryption</h3>

<a href="https://www.base64decode.org/">Base64 Decode and Encode - Online</a><br>
<a href="https://www.dcode.fr/binaryfuck-language">Binaryfuck Language - Online Decoder, Encoder, Translator</a><br>
<a href="https://md5decrypt.net/en/Brainfuck-translator/">Online Brainfuck Decoder</a><br>
<a href="https://appdevtools.com/base64-encoder-decoder">Base64 Encoder / Decoder Online - AppDevTools</a><br>
<a href="https://gchq.github.io/CyberChef/">CyberChef</a><br>
<a href="https://md5hashing.net/hash">Hash decoder and calculator</a><br>
<a href="https://www.calculator.net/hex-calculator.html?b2dnumber1=7a69&calctype=b2d&x=Calculate#hex2decimal">Hex Calculator</a><br>
<a href="https://crackstation.net/">CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.</a><br>
<a href="https://hashkiller.io/listmanager">Hashkiller.io - List Manager</a><br>
<a href="https://www.urldecoder.org/">URL Decode and Encode - Online</a><br>
<a href="https://devtoolcafe.com/tools/des">DES Encryption / Decryption Tool</a><br>
<a href="https://md5decrypt.net/en/">Encrypt and Decrypt your MD5 hashes online</a><br>
<a href="https://www.md5online.org/md5-decrypt.html">MD5 Online | Free MD5 Decryption, MD5 Hash Decoder</a><br>
<a href="https://hashcat.net/hashcat/">hashcat - advanced password recovery</a><br>
<a href="https://quipqiup.com/">quipqiup - cryptoquip and cryptogram solver</a><br>
<a href="https://hashes.com/en/decrypt/hash">Decrypt MD5, SHA1, MySQL, NTLM, SHA256, MD5 Email, SHA256 Email, SHA512, Wordpress, Bcrypt hashes for free online</a><br>
<a href="https://obf-io.deobfuscate.io/">Obfuscator.io Deobfuscator</a><br>
<a href="https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master">Files · kali/master · Kali Linux / Packages / hash-identifier · GitLab</a><br>
<a href="https://asecuritysite.com/hash/splunk_hash">Splunk Password Hashing - sha512crypt ($6$) SHA512 (Unix)</a><br>

<h3>Reconnaissance</h3>

<a href="https://www.wappalyzer.com/">Find out what websites are built with - Wappalyzer</a><br>
<a href="https://builtwith.com/">BuiltWith Technology Lookup</a><br>
<a href="https://www.peoplefinder.com/">People Finder - People Search, Background Checks & Phone Number Lookup</a><br>
<a href="https://www.talosintelligence.com/reputation_center">IP and Domain Intelligence Center || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence</a><br>

<h3>Network / DNS Tools</h3>

<a href="https://mxtoolbox.com/MXLookup.aspx">MX Lookup Tool - Check your DNS MX Records online - MxToolbox</a><br>
<a href="https://developer.shodan.io/">Shodan Developer</a><br>
<a href="https://wigle.net/">WiGLE: Wireless Network Mapping</a><br>
<a href="https://viewdns.info/">ViewDNS.info - Your one source for DNS related tools!</a><br>
<a href="https://www.ipvoid.com/">IP Address Tools, Network Tools, DNS Tools | IPVoid</a><br>
<a href="https://dmarcian.com/spf-survey/">SPF Surveyor - dmarcian</a><br>
<a href="https://protonvpn.com/pricing">Pricing | Proton VPN</a><br>
<a href="https://horizon.netscout.com/">Real-Time DDoS Attack Map | NETSCOUT Cyber Threat Horizon</a><br>
<a href="https://www.arin.net/resources/guide/request/">Requesting IP Addresses or ASNs - American Registry for Internet Numbers</a><br>

<h3>Phishing / Social Engineering</h3>

<a href="https://getgophish.com/">Gophish - Open Source Phishing Framework</a><br>
<a href="https://www.trustedsec.com/resources/tools/the-social-engineer-toolkit-set">TrustedSec | The Social Engineering Toolkit (SET)</a><br>
<a href="https://www.trustedsec.com/blog/intro-to-macros-and-vba-for-script-kiddies">TrustedSec | Intro to Macros and VBA for Script Kiddies</a><br>
<a href="https://defa.ng/">Defang Tool</a><br>

<h3>Privilege Escalation</h3>

<a href="https://lolbas-project.github.io/#">LOLBAS</a><br>
<a href="https://lolbas-project.github.io/lolbas/Binaries/Certutil/">Certutil | LOLBAS</a><br>
<a href="https://gtfobins.github.io/">GTFOBins</a><br>
<a href="https://book.hacktricks.xyz/linux-hardening/useful-linux-commands">Useful Linux Commands | HackTricks</a><br>

<h3>Persistence</h3>

<a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md">PayloadsAllTheThings/Methodology and Resources/Windows - Persistence.md at master · swisskyrepo/PayloadsAllTheThings · GitHub</a><br>
<a href="https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/">Persistence using RunOnceEx – Hidden from Autoruns.exe – Oddvar Moe's Blog</a><br>
<a href="https://www.netspi.com/blog/technical-blog/network-penetration-testing/establishing-registry-persistence-via-sql-server-powerupsql/">Establishing Registry Persistence via SQL Server with PowerUpSQL</a><br>
<a href="https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx">webshell/fuzzdb-webshell/asp/cmdasp.aspx at master · tennc/webshell · GitHub</a><br>

<h3>Forensics</h3>

<a href="https://www.autopsy.com/download/">Autopsy - Download</a><br>
<a href="https://www.exterro.com/digital-forensics-software/ftk-imager">FTK Imager - Forensic Data Imaging and Preview Solution | Exterro</a><br>
<a href="https://www.kroll.com/en-gb/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape">Kroll Artifact Parser And Extractor (KAPE) | Cyber Risk | Kroll</a><br>
<a href="https://stylesuxx.github.io/steganography/">Steganography Online</a><br>

<h3>Crypto & Blockchain</h3>

<a href="https://remix.ethereum.org/">Remix - Ethereum IDE</a><br>
<a href="https://etherscan.io/">Etherscan</a><br>

<h3>Cheatsheets</h3>

<a href="https://happycamper84.medium.com/windows-reverse-shells-cheatsheet-5eeb09b28c8e">Windows Reverse Shells Cheatsheet | by Rich | Medium</a><br>
<a href="https://podalirius.net/en/articles/windows-reverse-shells-cheatsheet/">Windows Reverse Shells Cheatsheet</a><br>
<a href="https://devhints.io/bash">Bash scripting cheatsheet</a><br>
<a href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html">Password Storage - OWASP Cheat Sheet Series</a><br>
<a href="https://docs.pwntools.com/en/stable/">pwntools — pwntools 4.12.0 documentation</a><br>
<a href="https://www.stationx.net/nmap-cheat-sheet/">Nmap Cheat Sheet 2024: All the Commands & Flags</a><br>
<a href="https://vim.rtorr.com/">Vim Cheat Sheet</a><br>
<a href="https://yara.readthedocs.io/en/stable/writingrules.html">Writing YARA rules — yara 4.4.0 documentation</a><br>
<a href="https://frida.re/docs/examples/windows/">Windows | Frida • A world-class dynamic instrumentation toolkit</a><br>
<a href="https://pentestmonkey.net/tools/reverse-shell-cheat-sheet">Reverse Shell Cheat Sheet | pentestmonkey</a><br>
<a href="https://blog.didierstevens.com/programs/oledump-py/">oledump.py | Didier Stevens</a><br>
<a href="https://wiki.zacheller.dev/pentest/privilege-escalation/spawning-a-tty-shell">Spawning a TTY Shell | SecWiki</a><br>
<a href="http://pinvoke.net/index.aspx">pinvoke.net: the interop wiki!</a><br>

<h3>Miscellaneous Tools</h3>

<a href="https://geoguessr.com/">GeoGuessr - Let's explore the world!</a><br>
<a href="https://imageresizer.com/">Image Resizer</a><br>
<a href="https://regexr.com/">RegExr: Learn, Build, & Test RegEx</a><br>
<a href="https://live.sysinternals.com/">live.sysinternals.com - /</a><br>
<a href="https://www.onlinegdb.com/">GDB online Debugger | Compiler - Code, Compile, Run, Debug online C, C++</a><br>
<a href="https://vectr.io/features/">Features | VECTR</a><br>
<a href="https://scapy.net/">Scapy</a><br>
<a href="https://cheatengine.org/">Cheat Engine</a><br>
<a href="https://ngrok.com/download">Ngrok Download</a><br>
<a href="https://www.openstack.org/">Open Source Cloud Computing Infrastructure - OpenStack</a><br>
<a href="https://www.srihash.org/">SRI Hash Generator</a><br>
<a href="https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php">php-reverse-shell.php</a><br>
<a href="https://ffmpeg.org/">FFmpeg</a><br>
<a href="https://app.diagrams.net/">draw.io</a><br>
<a href="https://www.convertcsv.com/url-extractor.htm">Extract URLs</a><br>
<a href="https://crontab.guru/">Crontab.guru - The cron schedule expression generator</a><br>
<a href="https://crontab-generator.org/">Crontab Generator - Generate crontab syntax</a><br>
<a href="https://codebeautify.org/javascript-obfuscator">JavaScript Obfuscator Online: JS Code Obfuscator</a><br>
<a href="https://user-agents.net/">User Agents</a><br>

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
<a href="https://github.com/NationalSecurityAgency/ghidra/releases">Releases · NationalSecurityAgency/ghidra</a><br>
<a href="https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1">PowerSploit/Exfiltration/Get-GPPPassword.ps1 at master · PowerShellMafia/PowerSploit</a><br>
<a href="https://github.com/SnaffCon/Snaffler">SnaffCon/Snaffler: a tool for pentesters to help find delicious candy, by @l0ss and @Sh3r4 (Twitter: @/mikeloss and @/sh3r4_hax)</a><br>
<a href="https://github.com/danielmiessler/SecLists">GitHub - danielmiessler/SecLists: SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.</a><br>
<a href="https://github.com/fortra/impacket">fortra/impacket: Impacket is a collection of Python classes for working with network protocols.</a><br>
<a href="https://github.com/leoloobeek/LAPSToolkit">leoloobeek/LAPSToolkit: Tool to audit and attack LAPS environments</a><br>
<a href="https://github.com/radareorg/radare2">radareorg/radare2: UNIX-like reverse engineering framework and command-line toolset</a><br>
<a href="https://github.com/samratashok/nishang">nishang/Gather at master · samratashok/nishang</a><br>
<a href="https://github.com/sshuttle/sshuttle">sshuttle</a><br>
<a href="https://github.com/icsharpcode/ILSpy">GitHub - icsharpcode/ILSpy: .NET Decompiler with support for PDB generation, ReadyToRun, Metadata (&more) - cross-platform!</a><br>
<a href="https://github.com/mandiant/flare-vm">mandiant/flare-vm: A collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering environment on a VM.</a><br>
<a href="https://github.com/mandiant/capa">mandiant/capa: The FLARE team's open-source tool to identify capabilities in executable files.</a><br>
<a href="https://github.com/cuckoosandbox/cuckoo">cuckoosandbox/cuckoo: Cuckoo Sandbox is an automated dynamic malware analysis system</a><br>
<a href="https://github.com/InQuest/awesome-yara">InQuest/awesome-yara: A curated list of awesome YARA rules, tools, and people.</a><br>
<a href="https://github.com/Neo23x0/Loki">Neo23x0/Loki: Loki - Simple IOC and YARA Scanner</a><br>
<a href="https://github.com/Neo23x0/Fenrir">Neo23x0/Fenrir: Simple Bash IOC Scanner</a><br>
<a href="https://github.com/Neo23x0/yarGen">Neo23x0/yarGen: yarGen is a generator for YARA rules</a><br>

<h3>[unsorted]</h3>

<a href="https://snyk.io/plans/">Plans and pricing | For teams of all sizes | Snyk</a><br>
<a href="https://www.aikido.dev/">Aikido — AppSec Platform For Code & Cloud Security</a><br>

