import pefile
import hashlib
import sys

def calculate_md5(data):
    md5_hash = hashlib.md5()
    with open(data, "rb") as file:
        while chunk := file.read(4096):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def get_architecture_name(machine_value):
    machine_names = {
        0x14c: "x86",
        0x8664: "x64",
    }
    return machine_names.get(machine_value, "Unknown")

def print_pe_info(data):
    try:
        pe = pefile.PE(data)
    except pefile.PEFormatError as e:
        return
    
    machine = pe.FILE_HEADER.Machine
    architecture = get_architecture_name(machine)

    print("\n\nName:", sys.argv[1])
    print("Architecture:", architecture)
    print("Size:", len(pe.__data__))
    print("MD5 Hash:", calculate_md5(data))

    pe.close()