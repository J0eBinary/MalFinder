from Modules import entropyCalc, formatting

def print_sections_info(file):
    print("\n" * 2)
    print("\033[93m{:<20} {:<15} {:<15} {:<15} {:<15}\033[00m".format("Section Name", "Virtual Size", "Physical Size", "Entropy", "Note"))
    print("="*120)

    for section in file.sections:
        section_name = section.Name.decode('utf-8').rstrip('\x00')
        virtual_size = section.Misc_VirtualSize
        physical_size = section.SizeOfRawData
        entropy = entropyCalc.calculate_entropy(section.get_data())
        
        if entropy> 7 :
            note = "High Entropy Detected"
        else:
            note = ""
        
        if virtual_size > physical_size:
            if note == "" :
                note = "Larger Virtual Size"
            else:
                note += ", Larger Virtual Size"
            formatting.printRedSec(section_name, virtual_size, physical_size, entropy , note)
        else:
            formatting.printGreenSec(section_name, virtual_size, physical_size, entropy ,note)
            
    print("="*120)
    print("\n" * 2)