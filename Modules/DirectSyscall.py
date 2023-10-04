import capstone
import pefile
from Modules import formatting

def find_Directsyscalls(binary_file_path):
    checkSyscall = True
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    pe = pefile.PE(binary_file_path)
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Find the code section based on entry point
    for section in pe.sections:
        if section.VirtualAddress <= entry_point < section.VirtualAddress + section.SizeOfRawData:
            code_section = section
            break
    else:
        print("Code section not found.")

    code_data = code_section.get_data()
    prev_insn = None  # previous instruction
    prev_prev_insn = None  # instruction before the previous one

    for insn in md.disasm(code_data, entry_point):
        if 'syscall' in insn.mnemonic:
            if checkSyscall == True:
                formatting.printYellow("\n\nDirect Syscall Usage Detected")
                checkSyscall = False
            print("-" * 50)
            if prev_insn:
                print(f"0x{prev_insn.address:016x}: {prev_insn.mnemonic} {prev_insn.op_str}")
            if prev_prev_insn:
                print(f"0x{prev_prev_insn.address:016x}: {prev_prev_insn.mnemonic} {prev_prev_insn.op_str}")
            print(f"0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}")
            print("-" * 50)
        prev_prev_insn = prev_insn
        prev_insn = insn
    print("\n\n")