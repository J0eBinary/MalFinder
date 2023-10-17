#green,red, and yellow colors 
def printGreen(text): print("\033[92m{}\033[00m".format(text))
def printYellow(text): print("\033[93m{}\033[00m".format(text))
def printRed(text): print("\033[91m{}\033[00m".format(text))

def printGreenSec(section_name, virtual_size, physical_size, entropy, note):
    print("\033[92m{:<20} {:<15} {:<15} {:<15.2f} {:<15} \033[00m".format(section_name, virtual_size, physical_size, entropy, note))
def printRedSec(section_name, virtual_size, physical_size, entropy,note):
    print("\033[91m{:<20} {:<15} {:<15} {:<15.2f} {:<15} \033[00m".format(section_name, virtual_size, physical_size, entropy, note))