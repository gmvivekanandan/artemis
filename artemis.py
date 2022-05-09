import argparse
import os
import sys
import json
from pylxd import Client

from static import *

# PATH
base_path = os.getcwd()
report_path = base_path+"/reports"

# PARSER
parser = argparse.ArgumentParser()
parser.add_argument("--elf", help="toggle for ELF files", action="store_true")
parser.add_argument("file", help="the file to analyse")
args = parser.parse_args()

# PARSE ARGUMENTS
file_name = args.file
is_elf = args.elf

# CHECK IF FILE EXISTS
is_exists = os.path.isfile(file_name)
if(is_exists):
    print("Checking for /reports directory...")
    try:
        os.mkdir(report_path)  # MAKE REPORTS DIRECTORY
    except OSError as error:
        print("Directory exists!\n")
        pass
else:
    print("File does not exist in the current directory!")
    sys.exit(1)

# INSTANTIATE REPORT FILE
if(is_elf):
    report_file_name = file_name.split()[0]
else:
    report_file_name = file_name.split('.')[0]
final_report = report_path+"/"+report_file_name+".txt"

# OPEN REPORT FILE
f = open(final_report, 'w')

# GENERATE REPORT
f.write("=====[STATIC ANALYSIS RESULTS]=====\n\n")
print("=====[STATIC ANALYSIS RESULTS]=====\n")
static = Static(file_name)

file_type = static.filetype()
print(f"FileType: {file_type}", end='')
f.write(f"FileType: {file_type}")

file_size = static.get_filesize()
print(f"Size of the file: {file_size} bytes")
f.write(f"Size of the file: {file_size} bytes\n")

file_md5 = static.get_md5()
print(f"md5 checksum: {file_md5}\n")
f.write(f"md5 checksum: {file_md5}\n\n")

print("+++++[VIRUSTOTAL RESULTS]+++++\n")
f.write("+++++[VIRUSTOTAL RESULTS]+++++\n\n")
virustotal_results = static.virus_total()
if(virustotal_results == None):
    f.write("No results found!\n\n")
    print("No results found!\n\n")
else:
    sorted_results = virustotal_results["data"]["attributes"]
    f.write(json.dumps(sorted_results, indent=2))
    f.write("\n\n")
    print("Check the report file for full Virustotal results\n")
    # THREAT CATEGORY
    category = sorted_results["popular_threat_classification"]["popular_threat_category"]
    print(f"Popular categories: \n{json.dumps(category, indent=2)}\n")
    # THREAT NAME
    name = sorted_results["popular_threat_classification"]["popular_threat_name"]
    print(f"Popular names: \n{json.dumps(name, indent=2)}\n")
    # AV DATA
    av_data = sorted_results["last_analysis_stats"]
    print(f"Popular AV detection: \n{json.dumps(av_data, indent=2)}\n")
    # POPULAR AV SOLUTION RESULTS
    av_results = sorted_results["last_analysis_results"]
    print(f"Popular AV results: \n{json.dumps(av_results, indent=2)}\n\n")

print("+++++[YARA ANALYSIS]+++++\n")
f.write("+++++[YARA ANALYSIS]+++++\n\n")
yara_results = static.yara()
if yara_results == []:
    print("No results matching any YARA rules!\n")
    print("Try changing the YARA rule in /config/capabilities.yara with other yara rules\nDO NOT CHANGE THE NAME OF THE FILE!\n")
    f.write("No results matching any YARA rules!\n\n")
    f.write("Try changing the YARA rule in /config/capabilities.yara with other yara rule file\nDO NOT CHANGE THE NAME OF THE FILE!\n\n")
else:
    print(yara_results)
    f.write(str(yara_results))
    f.write("\n\n")

print("+++++[STRINGS ANALYSIS]+++++\n")
f.write("+++++[STRINGS ANALYSIS]+++++\n\n")
strings_results = static.strings()
print(strings_results)
f.write(strings_results)
f.write("\n")

if(is_elf):
    print("+++++[ELF ANALYSIS]+++++\n")
    f.write("+++++[ELF ANALYSIS]+++++\n\n")

    file_header_results = static.file_header()
    print(file_header_results)

    program_header_results = static.program_header()
    print(program_header_results)

    section_header_results = static.section_header()
    print(section_header_results)

    symbol_results = static.symbols()
    print(symbol_results)

    print("Entire ELF analysis written to the report file\n")
    read_elf_results = static.read_elf()
    f.write(read_elf_results)
    f.write("\n\n")

print("+++++[DEPENDENCIES]+++++\n")
f.write("+++++[DEPENDENCIES]+++++\n\n")
dependencies_results = static.dependencies()
print(dependencies_results)
f.write(dependencies_results)
f.write("\n\n")

# DYNAMIC ANALYSIS
f.write("=====[DYNAMIC ANALYSIS RESULTS]=====\n\n")
print("=====[DYNAMIC ANALYSIS RESULTS]=====\n")

# CHECK IF LXD IS INSTALLED
lxd_exists = os.path.isfile("/snap/bin/lxd")
if(lxd_exists):
    print("LXD exists, checking for containers...\n")
else:
    print("LXD is not installed, Please install LXD to continue...")
    exit(1)

# INSTANTIATE LXD CLIENT
client = Client()

# CHECK IF CONTAINER EXISTS ELSE CREATE CONTAINER
container_exists = client.instances.exists("kali")
if(container_exists):
    container_config = client.instances.get("kali").config
else:
    print("Container does not exist,Creating a container")
    config = {'name': 'kali', 'source': {'type': 'image',
                                         'mode': 'pull', 'server': "https://images.linuxcontainers.org", 'protocol': 'simplestreams', 'alias': "kali/current/amd64"}, 'profiles': ['default']}
    instance = client.instances.create(config, wait=True)
    client.instances.get("kali").start(wait=True)
    container_config = client.instances.get("kali").config

# GET CONTAINER CONFIGS
host_interface = container_config["volatile.eth0.host_name"]

# CLOSE REPORT FILE
f.close()
