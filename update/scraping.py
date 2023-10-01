from bs4 import BeautifulSoup
import requests
import datetime
import json

import sys

sys.path.insert(0, "..")
from utility.config import Config
from utility.logger import Logger


"""
    @@ All the details of API functions will scraping from: https://malapi.io/ .
"""
class Malapi:
    url    : str = "https://malapi.io/"
    data   : dict = {}
    logger : Logger

    def __init__(self, color_state=True) -> None:
        self.config = Config()
        self.logger = Logger(color_state)

    # Check total function from https://malapi.io/, And compare it with config.json["total_functions"] (last record).
    # If there're new functions it will append a new file.
    def check_for_update(self):
        soup = self.get_bsoup()
        table_body = soup.select("#scrollable-table-body")[0]
        total_function = len(
            table_body.find_all("a", class_="white-link map-item-link")
        )
        if total_function != self.get_last_record():
            self.update()
        self.logger.msg("[YELLOW]There is no need to update.")

    # Setup BeautifulSoup.
    def get_bsoup(self, url=None) -> BeautifulSoup:
        if url:
            page = requests.get(url).text
            return BeautifulSoup(page, "html.parser")
        page = requests.get(self.url).text
        return BeautifulSoup(page, "html.parser")

    # Update: Create new file contain all functions from https://malapi.io/.
    def update(self) -> None:
        """
        @@ Read https://malapi.io/ main table.
            -: After reading ALL columns, append APIs to file through `self.create_file()`
            -: *MUST READ ALL FUNCTIONS BEOFRE ADD TO JSON FILE OR JSON FILE WILL BE BROKEN*
        """
        soup = self.get_bsoup()
        table_body = soup.select("#scrollable-table-body")[0]
        total_function = len(
            table_body.find_all("a", class_="white-link map-item-link")
        )
        counter = 0
        for col in range(0, 8):
            rows = table_body.find_all("tbody")[col].find_all(
                "a", class_="white-link map-item-link"
            )
            for function in rows:
                self.data[function.get_text()] = self.get_details(function.get_text())
                counter += 1
                self.update_log(counter, rows, col, 7)
            counter = 0
        self.create_file()
        self.set_new_record(total_function)
        self.logger.msg("\n[GREEN]file has been updated!")

    # Print Update log.
    def update_log(self, counter, rows, col, cols):
        self.logger.msg(
            f"[YELLOW]Updateing[REST] : "
            f"columns    :  [GREEN]{col}/{cols}[REST] | "
            f"functions  :  [GREEN]{counter}/{len(rows)}[REST] | "
            f"percentage :  [GREEN]{int(counter/len(rows) * 100)}%    ",
            end="\r",
        )

    # Get APIs details from https://malapi.io/winapi/{FUNCTION_NAME}
    def get_details(self, function_name: str) -> dict:
        url = self.url + "winapi/" + function_name
        soup = self.get_bsoup(url)
        details = {
            "describe": soup.find_all("div", class_="detail-container")[1]
            .find("div", class_="content")
            .get_text()
            .strip(),
            "library": soup.find_all("div", class_="detail-container")[2]
            .find("div", class_="content")
            .get_text()
            .strip(),
            "associated_attacks": soup.find_all("div", class_="detail-container")[3]
            .find("div", class_="content")
            .get_text()
            .strip()
            .split(),
            "documentation": soup.find_all("div", class_="detail-container")[4]
            .find("div", class_="content")
            .get_text()
            .strip(),
        }
        return details

    # Create file /APIs/WIN-APIs-DAY-MONTH-YEAR.json
    def create_file(self) -> None:
        date = datetime.datetime.now().strftime("%d-%m-%y")
        file = f"APIs/WIN-APIs-{date}.json"
        json_object = json.dumps(self.data, indent=4)
        with open(file, "+a") as f:
            f.write(json_object)
        self.set_new_api_file(file)

    # Set new total_functions record
    def set_new_record(self, new_record: int) -> None:
        self.config.config["total_functions"] = new_record
        self.config.push_config()

    # Get last total_functions record
    def get_last_record(self) -> None:
        return self.config.config["total_functions"]

    # Set new api file config.json["api_file"]
    def set_new_api_file(self, new_filename: str) -> None:
        self.config.config["api_file"] = new_filename
        self.config.push_config()
