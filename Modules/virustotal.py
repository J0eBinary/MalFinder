import os
import hashlib
import requests
from Modules import formatting

def calculate_md5(data):
    md5_hash = hashlib.md5()
    with open(data, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def scan_with_virustotal(api_key, file_hash):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        "apikey": api_key,
        "resource": file_hash
    }
    response = requests.get(url, params=params)
    return response.json()

def parseScan(data):
    api_key = None
    if os.path.exists("Modules/api.txt") and os.path.getsize("Modules/api.txt") > 0:
        with open("Modules/api.txt", "r") as key_file:
            api_key = key_file.read().strip()

    if api_key:

        md5_hash = calculate_md5(data)
        report = scan_with_virustotal(api_key, md5_hash)

        if report.get("response_code") == 1:
            formatting.printYellow("VirusTotal Scan")
            print("=" * 120)
            print("\033[91m\nFile detected by {} out of {} antivirus engines".format(report["positives"], report["total"]))
            print("Link: ",report["permalink"] , "\n\033[00m")
            print("=" * 120)
        else:
            formatting.printYellow("VirusTotal Scan")
            print("=" * 120)
            formatting.printYellow("\nFile not found on VirusTotal\n")
            print("=" * 120)