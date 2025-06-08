# UNZIPRAR - Password brute-force and extractor tool
# For ethical and educational use only.
# Unauthorized use is strictly prohibited.

import rarfile
import os
import sys
import shutil

def configure_rar_backend():
    if sys.platform.startswith("win"):
        unrar_path = os.path.join(os.getcwd(), "UnRAR.exe")
        if not os.path.exists(unrar_path):
            print("[-] 'UnRAR.exe' not found in current directory.")
            sys.exit(1)
        rarfile.UNRAR_TOOL = unrar_path
        rarfile.PATH_SEP = '\\'              # Required for Windows paths
        rarfile.USE_BSDTAR = False           # Force disable BSDTAR fallback
        rarfile.USE_UNRAR_TOOL = True        # Force enable UNRAR tool
        print(f"[+] Using UnRAR backend at: {unrar_path}")
    else:
        if shutil.which("unrar"):
            rarfile.UNRAR_TOOL = "unrar"
            rarfile.USE_UNRAR_TOOL = True
            rarfile.USE_BSDTAR = False
            print("[+] Using system 'unrar'")
        else:
            print("[-] 'unrar' not found. Please install it with your package manager.")
            sys.exit(1)

### CREATED by Muhammad Zidan Ramadhan ###