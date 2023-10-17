REST   : str  = "\033[00m"
GREEN  : str  = "\033[92m"
YELLOW : str  = "\033[93m"
RED    : str  = "\033[91m"
WHITE  : str  = "\033[37m"

colors = {
    "REST"   : REST,
    "GREEN"  : GREEN,
    "YELLOW" : YELLOW,
    "RED"    : RED,
    "WHITE"  : WHITE
}
class Logger:
    color_state : bool
    def __init__(self, color_state = True) -> None:
        self.color_state = color_state

    def msg(self, message: str, end="\n"):
        if not self.color_state:
            for k, _ in colors.items():
                message = message.replace(f"[{k}]" , "")
        for k, v in colors.items():
            message = message.replace(f"[{k}]", v)
        message += REST
        print(message, flush=True, end=end)
