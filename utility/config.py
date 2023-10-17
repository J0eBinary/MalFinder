"""
    This will provide API for config.json
"""
import json


class Config:
    config_file: str
    config: dict = {}

    def __init__(self, config_file="config.json") -> None:
        self.config_file = config_file
        self.init_conifg()

    def init_conifg(self):
        with open(self.config_file, "r") as f:
            self.config = json.load(f)

    def push_config(self):
        with open(self.config_file, "w") as f:
            json.dump(self.config, f)
        self.init_conifg()
