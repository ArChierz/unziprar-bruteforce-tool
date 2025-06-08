# UNZIPRAR - Password brute-force and extractor tool
# For ethical and educational use only.
# Unauthorized use is strictly prohibited.

from zipfile import ZipFile
import rarfile
import argparse
import os
from configuration import configure_rar_backend

def visual():
    print("="*70)
    print("="*70)
    print("="*15,end="")
    print(" "*40,end="")
    print("="*15)
    print("="*8,end="  ")
    print("ZIP/RAR Password Brute Forcer and Extractor Tool",end="    ")
    print("="*8)
    print("="*15,end="")
    print(" "*40,end="")
    print("="*15)
    print("="*70)
    print("="*70)

def check_file_type(filename):
    try:
        with open(filename, "rb") as f:
            file_start = f.read(12)
            if file_start.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
                return "zip"
            elif file_start.startswith(b'Rar!\x1a\x07\x00') or file_start.startswith(b'Rar!\x1a\x07\x01\x00'):
                return "rar"
            else:
                return None
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return None

def password_check(password, mod, info=None, extract=False, path='.'):
    if not extract:
        try:
            with mod.open(info,pwd=(password.encode())) as myfile:
                content = myfile.read()
                print(f"[+] Password Correct!")
                print(f"[+] Successfully read: {info.filename}")
                print(f"content: \n{content.decode(errors='replace')}")
        except Exception as e:
            print(f"[-] Password '{password}' Failed to read '{info.filename}': {e}")
    else:
        try:
            mod.extractall(path, pwd=(password.encode()))
            print(f"[+] Successfully extracted, path: {os.path.abspath(path)}")
        except Exception as e:
            print(f"[-] Failed to extract '{info.filename}': {e}")

def wordlist_check(wordlist, mod, info=None, extract=False, path='.'):
    if not extract:
        try:
            with open(wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                counter = 0
                for line in f:
                    attempt = line.strip()
                    if not attempt:
                        continue
                    counter += 1
                    print(f"[BRUTE] Trying for password: {attempt}")
                    print(f"[BRUTE] Password attempts: {counter}")
                    try:
                        with mod.open(info,pwd=(attempt.encode())) as myfile:
                            content = myfile.read()
                            print(f"[+] Password Correct: {attempt}")
                            print(f"[+] Successfully read: {info.filename}")
                            print(f"content: \n{content.decode(errors='replace')}")
                    except Exception as e:
                        print(f"[-] Password '{attempt}' Failed to read '{info.filename}': {e}")
        except Exception as e:
            print(f"[-] Failed to open wordlist: {e}")
    else:
        try:
            with open(wordlist, 'r', encoding="utf-8", errors="ignore") as f:
                counter = 0
                for line in f:
                    attempt = line.strip()
                    if not attempt:
                        continue
                    counter += 1
                    print(f"[BRUTE] Trying for password: {attempt}")
                    try:
                        mod.extractall(path=path, pwd=attempt.encode())
                        print(f"[+] Password Correct: {attempt} | Extracted all files to: {path}")
                        break  # success, stop
                    except Exception as e:
                        print(f"[-] Password '{attempt}' failed: {e}")
        except Exception as e:
            print(f"[-] Failed to open wordlist: {e}")

def read_zip_file(file_path,wordlist=None, password=None):
    try:
        with ZipFile(file_path, 'r') as myzip:
            infos =  myzip.infolist()
            if not infos:
                raise ValueError("Archive is empty!")
            for info in infos:
                print(f"File: {info.filename}, Size: {info.file_size} bytes")

                if password:
                    password_check(password, myzip, info)
                
                elif wordlist:
                    wordlist_check(wordlist, myzip, info)
                else:
                    print("[-] No password or wordlist provided")
                    
                    if info.flag_bits & 0x1:
                        print(f"[-] '{info.filename}' is encrypted and password is required. Consider using -P or -w to supply a password or a wordlist file")
                    else:
                        try: 
                            with myzip.open(info) as myfile:
                                content = myfile.read()
                                print(f"[+] Successfully read: {info.filename}")
                                print(f"content: \n{content.decode()}")
                        except Exception as e:
                            print(f"[-] Failed to read '{info.filename}': {e}")

    except Exception as e:
        print(f"[-] Error reading file: {e}")

def read_rar_file(file_path, wordlist=None, password=None):
    try:
        with rarfile.RarFile(file_path, 'r') as myrar:
            infos =  myrar.infolist()
            if not infos:
                raise ValueError("Archive is empty!")
            
            print(f"[+] Listing contents of: {file_path}")
            for info in infos:
                print(f"File: {info.filename}, Size: {info.file_size} bytes, Password: {info.needs_password()}")

                if password:
                    password_check(password, myrar, info)
                
                elif wordlist:
                    wordlist_check(wordlist, myrar, info)
                else:
                    print("[-] No password or wordlist provided")
                
                    if info.flag_bits & 0x1:
                            print(f"[-] '{info.filename}' is encrypted and password is required. Consider using -P or -w to supply a password or a wordlist file")
                    else:
                        try:
                            with myrar.open(info) as myfile:
                                content = myfile.read()
                                print(f"[+] Successfully read: {info.filename}")
                                print(f"content: \n{content.decode()}")
                        except Exception as e:
                            print(f"[-] Failed to read '{info.filename}': {e}")
    
    except Exception as e:
        print(f"[-] Error reading file: {e}")

def extract_zip_file(file_path, extract, wordlist=None, password=None,path='.'):
    if not extract:
        exit(1)
    try:
        with ZipFile(file_path, 'r') as myzip:
            infos =  myzip.infolist()
            if not infos:
                raise ValueError("Archive is empty!")
            
            print(f"[+] Listing contents of: {file_path}")
            for info in infos:
                print(f"File: {info.filename}, Size: {info.file_size} bytes")
                # Extract all item
                if password:
                    password_check(password, myzip, info, True, path)
                
                elif wordlist:
                    wordlist_check(wordlist, myzip, info, True, path)
                else:
                    print("[-] No password or wordlist provided")
                    if info.flag_bits & 0x1:
                        print(f"[-] '{info.filename}' is encrypted and password is required. Consider using -P or -w to supply a password or a wordlist file")
                    else:
                        try:
                            myzip.extractall(path)
                            print(f"[+] Successfully extracted, path: {os.path.abspath(path)}")
                        except Exception as e:
                            print(f"[-] Failed to extract '{info.filename}': {e}")
    
    except Exception as e:
        print(f"[-] Error extract file: {e}")

def extract_rar_file(file_path, extract, wordlist=None, password=None, path='.'):
    if not extract:
        exit(1)
    try:
        with rarfile.RarFile(file_path, 'r') as myrar:
            infos =  myrar.infolist()
            if not infos:
                raise ValueError("Archive is empty!")
            
            print(f"[+] Listing contents of: {file_path}")
            for info in infos:
                print(f"File: {info.filename}, Size: {info.file_size} bytes, Password: {info.needs_password()}")
                # Extract all item
                if password:
                    password_check(password, myrar, info, True, path)
                
                elif wordlist:
                    wordlist_check(wordlist, myrar, info, True, path)
                else:
                    print("[-] No password or wordlist provided")
                    if info.flag_bits & 0x1:
                        print(f"[-] '{info.filename}' is encrypted and password is required. Consider using -P or -w to supply a password or a wordlist file")
                    else:
                        try:
                            myrar.extractall(path)
                            print(f"[+] Successfully extracted, path: {os.path.abspath(path)}")
                        except Exception as e:
                            print(f"[-] Failed to extract '{info.filename}': {e}")
    
    except Exception as e:
        print(f"[-] Error extract file: {e}")

def extract(file_path,  extract, wordlist=None, password=None, path=None):
    filetype = check_file_type(file_path)
    if not extract:
        exit(1)

    if filetype == "zip":
        print("[+] Filetype: ZIP")
        extract_zip_file(file_path, extract, wordlist, password, path)
    elif filetype == "rar":
        print("[+] Filetype: RAR")
        extract_rar_file(file_path, extract, wordlist, password, path)
    else:
        print("[-] Unsupported or unknown filetype")


def archive(file_path, wordlist=None, password=None, extract=None, path=None):
    filetype = check_file_type(file_path)
    if filetype == "zip":
        print("[+] Filetype: ZIP")
        read_zip_file(file_path, wordlist, password)
    elif filetype == "rar":
        print("[+] Filetype: RAR")
        read_rar_file(file_path, wordlist, password)
    else:
        print("[-] Unsupported or unknown filetype")
    
if __name__ == "__main__":
    visual()
    configure_rar_backend()

    parser = argparse.ArgumentParser(description="ZIP/RAR Password Brute Forcer and Extractor Tool")
    
    parser.add_argument("-a","--archive", required=True, help="Path to the ZIP or RAR file")
    parser.add_argument("-P","--password", help="Provide password to the file")
    parser.add_argument("-w","--wordlist", help="Path to the password wordlist file")
    parser.add_argument("-x","--extract", action="store_true", help="Extract Archived Content, provide the option without value is enough")
    parser.add_argument("-p","--path", help="Specify which path to extract the output", default=".")
    args = parser.parse_args()

    if not args.extract:
        archive(args.archive, args.wordlist, args.password, args.path)
    else:
        extract(args.archive, args.extract, args.wordlist, args.password, args.path)

### CREATED by Muhammad Zidan Ramadhan ###
