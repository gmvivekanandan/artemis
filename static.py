import subprocess
import os
import hashlib
import requests
import yara


class Static:

    def __init__(self, mal_file):
        self.file = mal_file
        self.md5 = ""

    def filetype(self):
        output = subprocess.check_output(["file", self.file], text=True)
        return output

    def get_filesize(self):
        output = os.path.getsize(self.file)
        return output

    def get_md5(self):
        with open(self.file, "rb") as f:
            self.md5 = hashlib.md5(f.read()).hexdigest()
            return self.md5

    def virus_total(self):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{self.md5}"
            headers = {
                "Accept": "application/json",
                # VIRUSTOTAL API KEY
                "x-apikey": "ba454f7f9a46f013dcef1daf5346aa86d89465d36cbb9ecd963a7a3279e109aa"
            }
            response = requests.request("GET", url, headers=headers)
            if(response.status_code == 404):
                return(None)
            else:
                response_data = response.json()  # CONVERT JSON TO PYTHON DICT
                return(response_data)
        except:
            print("No internet! Try again with internet")

    def yara(self):
        rule = yara.compile('config/capabilities.yara')
        matches = rule.match(self.file)
        return matches

    def strings(self):
        strings = subprocess.check_output(["strings", self.file], text=True)
        return strings

    def file_header(self):
        file_header = subprocess.check_output(
            ["readelf", "-h", self.file], text=True)
        return file_header

    def program_header(self):
        program_header = subprocess.check_output(
            ["readelf", "-l", self.file], text=True)
        return program_header

    def section_header(self):
        section_header = subprocess.check_output(
            ["readelf", "-S", self.file], text=True)
        return section_header

    def symbols(self):
        symbols = subprocess.check_output(
            ["readelf", "-s", self.file], text=True)
        return symbols

    def read_elf(self):
        read_elf = subprocess.check_output(
            ["readelf", "-a", self.file], text=True)
        return read_elf

    def dependencies(self):
        try:
            dependencies1 = subprocess.Popen(
                ["objdump", "-p", self.file], stdout=subprocess.PIPE)
            dependencies2 = subprocess.check_output(
                ["grep", "NEEDED"], stdin=dependencies1.stdout, text=True)
            dependencies1.stdout.close()
        except:
            return "No results found\n"
        return dependencies2
