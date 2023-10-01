import sys
from core.descriptor import Descriptor, Config
from core.file import File
from utility.logger import Logger
from update.scraping import Malapi

class MalFinder:
    file       : File
    config     : Config
    descriptor : Descriptor
    data       : dict
    logger     : Logger

    def __init__(self, file_path: str, color_state=True) -> None:
        self.file       = File(file_path)
        self.descriptor = Descriptor()
        self.data       = self.descriptor.data
        self.logger     = Logger(color_state)
        self.config     = Config().config
    # loop over INT of excutable then match with config.json["api_file"]
 
    def scan(self) -> None:
        for sym in self.file.symbols:
            if sym.name in self.data:
                function = self.descriptor.function(sym.name)
                (fname, faddr, fattacks, fdesc) = (
                    function.name,
                    hex(self.file.symbol[function.name]),
                    function.associated_attacks,
                    function.describe,
                )
                self.print_output(fattacks, fname, faddr, fdesc)
        print()

    def print_output(self, fattacks, fname, faddr, fdesc) -> None:
        print = lambda msg: self.logger.msg(msg)
        print("\n" + ("-" * 30) + f"[GREEN]Attacks[REST]:{fattacks}" + ("-" * 30) + "\n")
        print(f"[RED]{fname}[REST]({faddr})")
        print(f"[YELLOW]{fdesc}")


if __name__ == "__main__":
    COLOR_STATE = True
    args = sys.argv
    args_len = len(args)

    if args_len > 4 or args_len < 2:
        print = lambda msg: Logger(False).msg(msg)
        print("usage : ")
        print("\toptions = [ --no-color, --update ]")
        print("\tpython3 MalFinder.py [file] [options]")
        print("\tpython3 MalFinder.py --update\n")
        exit(1)
    if "--no-color" in args:
        COLOR_STATE = False
    if "--update" in args or args[1] == "--update":
        if args[1] == "--update":
            Malapi(COLOR_STATE).check_for_update()
            exit(0)
        Malapi(COLOR_STATE).check_for_update()
    
    MalFinder(args[1], COLOR_STATE).scan()
