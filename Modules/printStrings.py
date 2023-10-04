import pefile
import re
from Modules import formatting

def extract_strings_from_section(section):
    data = section.get_data()
    start = 0
    strings = []
    while start < len(data):
        string = ""
        while start < len(data) and data[start] >= 0x20 and data[start] <= 0x7E:
            string += chr(data[start])
            start += 1
        if string:
            strings.append(string)
        start += 1
    return strings

def is_ip_address(s):
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    return bool(ip_pattern.match(s))



def print_strings_in_binary(data):
    try:
        pe = pefile.PE(data)
    except pefile.PEFormatError as e:
        return

    
    all_strings = []
    for section in pe.sections:
        strings = extract_strings_from_section(section)
        all_strings.extend(strings)

    ip_addresses = [s for s in all_strings if is_ip_address(s)]
    if ip_addresses:
        formatting.printYellow("IP Addresses:")
        for ip in ip_addresses:
            formatting.printRed(ip)

    pe.close()
