from pefile import PE, ImportData


class Symbol:
    name    : str
    address : int

    def __init__(self, name: str, address: int) -> None:
        self.name = name
        self.address = address

    def __repr__(self) -> str:
        return f"Symbol<name: {self.name}, address: {self.address}>"


class File:
    path    : str
    pe      : PE
    symbol  : {str: str}
    symbols : list[Symbol]

    def __init__(self, file_path: str) -> None:
        self.path    = file_path
        self.pe      = PE(file_path)
        self.symbol  = {}
        self.symbols = []
        self.read_symbols()

    def read_symbols(self) -> None:
        [*map(self.maping, self.pe.DIRECTORY_ENTRY_IMPORT[0].imports)]

    def maping(self, data: ImportData) -> None:
        self.symbol[data.name.decode()] = data.address
        self.push_symbol(data.name.decode(), data.address)

    def push_symbol(self, name: str, address: int) -> None:
        self.symbols.append(Symbol(name, address))
