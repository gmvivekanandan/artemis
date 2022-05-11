from pylxd import Client


class Dynamic:

    def __init__(self, mal_file):
        self.file = mal_file
        self.client = Client()

    def strace(self):
        strace_output = self.client.instances.get('kali').execute(
            ["strace", f"./{self.file}"])
        return strace_output

    def ltrace(self):
        ltrace_output = self.client.instances.get('kali').execute(
            ["ltrace", f"./{self.file}"])
        return ltrace_output

    def tcpdump(self):
        self.client.instances.get('kali').execute([f"./{self.file}"])
