from __future__ import annotations
import json

import sys
sys.path.insert(0, '..')
from utility.config import Config

class Descriptor:
    config              : Config
    data                : dict
    name                : str 
    describe            : str
    library             : str
    associated_attacks  : list
    documentation       : str
    def __init__(self) -> None:
        self.data    = {}
        self.config  = Config().config
        self.load_win_api()
    def load_win_api(self) -> None:
        with open(self.config["api_file"], "r") as f:
            self.data = json.load(f)
    def function(self, function: str) -> Descriptor:
        self.name               = function
        self.describe           = self.data[function]["describe"]
        self.library            = self.data[function]["library"]
        self.associated_attacks = self.data[function]["associated_attacks"]
        self.documentation      = self.data[function]["documentation"]
        return self
    def __repr__(self) -> str:
        return "Descriptor< "\
        f"function: {self.name}, "\
        f"describe: {self.describe}, "\
        f"library: {self.library}, "\
        f"associated_attacks: {self.associated_attacks}, "\
        f"documentation: {self.documentation}>"
