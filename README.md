# UNZIPRAR Brute Force Tool

UNZIPRAR is a tool designed to extract content of ZIP and RAR archives, including the feature to brute force the password protected file powered by Python. It supports:
- Password brute forcing using a user-provided wordlist file or use a single password to open it.
- Handle both ZIP and RAR file formats seamlessly.
- Extracting all files from archives.
- Easy Command-line interface with flexible options.
- Integration with official `rarfile` backend and native Python `zipfile` module.
- Could be use in multiplatform.

The tool is ideal for cybersecurity enthusiasts and forensic analysts needing to access password-protected archives or perform brute-force attacks as part of their workflow.

---

# Installation Instruction
## Backend Dependency unrar
The file use the original binary provided by RARLAB, licensed for personal use.
**Install on Debian/Ubuntu:**
```
sudo apt update
sudo apt install unrar
```

**Install on Arch:**
```
sudo pacman -S unrar
```

# Example Usage
usage: main.py [-h] -a ARCHIVE [-P PASSWORD] [-w WORDLIST] [-x] [-p PATH]

ZIP/RAR Password Brute Forcer and Extractor Tool

options:
  -h, --help            show this help message and exit
  -a ARCHIVE, --archive ARCHIVE
                        Path to the ZIP or RAR file
  -P PASSWORD, --password PASSWORD
                        Provide password to the file
  -w WORDLIST, --wordlist WORDLIST
                        Path to the password wordlist file
  -x, --extract         Extract Archived Content, provide the option without value is enough
  -p PATH, --path PATH  Specify which path to extract the output


**HELP**
```
python main.py -h
```

**Extract ZIP/RAR file**
```
python main.py -a 'test.zip' -x
```

**Extract ZIP/RAR file with protected password and known password**
```
python main.py -a 'test.zip' -P password-here -x
```

**Extract ZIP/RAR file with protected password and unknown password**
```
python main.py -a 'test.zip' -w rockyou.txt -x
```

**Open ZIP/RAR file with protected password and unknown password**
```
python main.py -a 'test.zip' -w rockyou.txt 
```

**Open ZIP/RAR file with protected password and known password**
```
python main.py -a 'test.zip' -P password-here
```

**Open ZIP/RAR file**
```
python main.py -a 'test.rar' 
```

**Extract ZIP/RAR file and provide the path**
```
python main.py -a 'test.rar' -p .
```

## Sample Output:
```
python main.py -a testy.rar -P a -p . -x
======================================================================
======================================================================
===============                                        ===============
========  ZIP/RAR Password Brute Forcer and Extractor Tool    ========
===============                                        ===============
======================================================================
======================================================================
[+] Using UnRAR backend at: D:\unziprar_bruteforce_tool\UnRAR.exe
[+] Filetype: RAR
[+] Listing contents of: testy.rar
File: Tugas.txt, Size: 404 bytes, Password: True
[+] Successfully extracted, path: D:\
```

# Legal Disclaimer for Ethical Usage
This tool, **UNZIPRAR**, is developed strictly for educational purposes, ethical use, and legitimate security testiing.
- It is intended to help users recover their own password-procted ZIP and RAR files.
- Use with proper authorization.
- **You must not use this tool to gain unauthorized access** to data or systems that do not belong to you.
By using this tool, you agree to take full responsibility for your action. The developer is **not liable** for any misuse or damage resulting from the use of this software.