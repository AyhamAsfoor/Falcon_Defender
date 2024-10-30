import sys
import os
import time
import yara
import pyfiglet
import threading
import progressbar
from colorama import Fore, init
from tkinter import filedialog


def write_file(filename, string):
    with open(filename, "a") as output_file:
        output_file.write(string + "\n")


def mk_dict(rule_file):
    rule_dict8 = {}

    def parse_yara_file(file_path):
        with open(file_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line.startswith("include"):

                    include_path = line.split()[-1].strip('"')
                    include_file = os.path.join(os.path.dirname(file_path), include_path)

                    parse_yara_file(include_file)
                elif line.startswith("rule"):

                    rule_name = line.split()[1]
                    rule_dict8[rule_name] = file_path

    parse_yara_file(rule_file)
    return rule_dict8


def yara_sig_check(file, rules):
    try:
        matches = rules.match(file, timeout=60)
        if len(matches) > 0:

            filename = os.path.splitext(os.path.basename(file))[0]
            string = "File was hit: " + filename + " with rule: " + str(matches[0]) + "\n"
            write_file("Scan_Reports.txt", string)

            return file
    except None:
        pass


def quarantine_file(file_path, quarantine_folder):
    try:
        new_path = os.path.join(quarantine_folder, os.path.basename(file_path))
        os.rename(file_path, new_path)
        print(f"{Fore.RED}File {file_path} has been quarantined to {quarantine_folder}")
    except Exception as e:
        print(f"{Fore.RED}Error quarantining file: {str(e)}")


def dir_search(user_dir, rule_dict1):
    hit_files = []
    delete = str(input(f"{Fore.RED}Are you sure you want to delete a file? (y/n): "))
    timer_start = time.time()
    file_number = 0
    rules = yara.compile(filepaths=rule_dict1)

    print("Gathering your files...")
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for _ in files:
            file_number += 1
    print("Looks like you have " + str(file_number) + " files, scanning now...")
    time.sleep(5)
    file_counter = 0
    banner = f"====== Scan Report ======\n" \
             f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n" \
             f"Path: {user_dir}\n" \
             f"Files Scanned: {file_number}\n" \
             f"All malicious files that were identified below\n"\
             f"=========================\n"
    write_file("Scan_Reports.txt", banner)
    bar = progressbar.ProgressBar(maxval=file_number, widgets=[progressbar.Bar('=', '[', ']'), ' ',
                                                               progressbar.Percentage()])
    bar.start()
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for name in files:

            file_path = os.path.realpath(os.path.join(root, name))
            scanned_file = (yara_sig_check(file_path, rules))

            if scanned_file is not None and hit_files.__contains__(scanned_file) == False:
                scanned_file = os.path.splitext(os.path.basename(scanned_file))[0]
                hit_files.append(scanned_file)
                if delete in ["Y", "Ya", "y"]:
                    try:
                        os.remove(file_path)
                        print(f"{Fore.RED}{scanned_file}:Malicious file was deleted")
                    except None:
                        print(f"{Fore.RED}Error deleting file: {scanned_file} we will Quarantined")
                        quarantine_file(file_path, r"E:\project\CyberSecurity\pythonProject2\Quarantine Folder")
            file_counter += 1
            bar.update(file_counter)
    bar.finish()
    timer_end = time.time()
    total_time = timer_end - timer_start

    print(Fore.GREEN + "--------------------------------------------------------------------------------")
    print(Fore.BLUE + "This program discovered " + str(len(hit_files)) + " malicious files.")
    print(Fore.BLUE + "Please note: all malicious files that were identified can be found in 'Scan_Reports.txt'")
    print(Fore.BLUE + "Time taken to scan whole system: " + str(total_time))
    print(Fore.BLUE + "Total files found: " + str(file_number))
    print(Fore.GREEN + "--------------------------------------------------------------------------------")


def get_os_type():
    os_sys = sys.platform
    if os_sys == "win32":
        print("Platform detected: Windows")
        print("Executing commands... ")
        time.sleep(3)
        return "windows"
    if os_sys.startswith("linux"):
        print("Platform detected: Linux")
        print("Executing commands... ")
        time.sleep(3)
        return "linux"
    if os_sys == "darwin":
        print("Platform detected: Mac")
        print("Executing commands... ")
        time.sleep(3)
        return "mac"
    if os_sys == "cygwin":
        print("Platform detected: Windows/Cygwin")
        print("Executing commands... ")
        time.sleep(3)
        return "cygwin"
    else:
        print("Platform not detected, exiting...")
        sys.exit()


def get_rule_dir(os_type):
    if os_type == "windows":
        rule_path = "E:/project/CyberSecurity/pythonProject2/rule_files/rules.yar"
        return rule_path
    if os_type == "mac":
        rule_path = "/Users/Ayham_Asfoor/PycharmProjects/Antivirus/rules.yar"
        return rule_path
    if os_type.startswith("linux"):
        rule_path = "/home/Ayham_Asfoor/PycharmProjects/Antivirus/rules.yar"
        return rule_path
    return None


def main(dir_name, type_string):
    global rule_dict
    print("Attempting to detect your system configuration... ")
    time.sleep(3)
    os_main = get_os_type()
    if type_string == 0:
        if os_main in ["windows", "mac", "linux"]:
            rule_path = get_rule_dir(os_main)
            if rule_path:
                rule_dict = mk_dict(rule_path)
                dir_search(dir_name, rule_dict)
        else:
            print("Unsupported OS.")
    elif type_string == 1:
        if os_main in ["windows", "mac", "linux"]:
            rule_path = get_rule_dir(os_main)
            if rule_path:
                rule_dict = mk_dict(rule_path)
                rules = yara.compile(filepaths=rule_dict)
                scanned_file = yara_sig_check(dir_name, rules)
                if scanned_file:
                    print(f"File was hit: {scanned_file} is a malicious file.")
                else:
                    print("The file you scanned is NOT a malicious file.")
        else:
            print("Unsupported OS.")


def service_one():
    dir_file = input(Fore.YELLOW + "Select file or directory:")
    if dir_file in dir_file in ["File", "file", "FILE"]:
        file_path = filedialog.askopenfilename(
            title='Select file or directory',
            filetypes=(('Image', '*.png'), ('Text Files', '*.txt'), ('All Files', '*.*')),
            initialdir='/',
        )
        return file_path, 1
    if dir_file in ["Directory", "directory", "dir", "Dir", "DIR"]:
        file_path = filedialog.askdirectory(title='Select file')
        return file_path, 0


def get_drive():
    drives1 = []
    for drive_letter in range(ord('A'), ord('Z') + 1):
        drive1 = f'{chr(drive_letter)}:\\'
        if os.path.exists(drive1):
            drives1.append(drive1)
    return drives1


def timer():
    def initial_main():
        main(main_path, 0)
        timer()
    global delay_seconds
    timer_value = threading.Timer(delay_seconds, initial_main)
    timer_value.start()


if __name__ == "__main__":
    delay_seconds = 60
    rule_dict = 0
    main_path = 'E:/project/CyberSecurity/pythonProject2/test'
    init(autoreset=True)
    custom_fig = pyfiglet.Figlet(font='big')
    ascii_art = custom_fig.renderText('A n t i    V i r u s')
    colored_ascii_art = f'{Fore.BLUE}{ascii_art}'
    print(colored_ascii_art)
    print(Fore.BLUE + "[1] Select a specific Directory/File by Browse.\n"
          "[2] Select a specific Directory/File by Path.\n"
          "[3] Select a Drives to scan.\n"
          "[4] Default settings for Periodic scan.\n")

    service = input(Fore.YELLOW + "Please Select a service:")
    if str(service) == '1':
        path, type_ser = service_one()
        if path is "":
            print(Fore.RED + "Error, Pleas reselect a path.")
            path, type_ser = service_one()
        main(path, type_ser)
    if str(service) == '2':
        path = input(Fore.YELLOW + 'input a path would to scan:')
        if path is "":
            print(Fore.RED + "Error, Pleas reselect a path.")
            path = input(Fore.YELLOW + 'input a path would to scan:')
        if not os.path.isfile(path):
            type_ser = 0
        else:
            type_ser = 1
        main(path, type_ser)
    if str(service) == '3':
        drive_names = get_drive()
        print(Fore.YELLOW + 'Your Drives :')
        for drive in drive_names:
            print(Fore.MAGENTA + drive)
        path = input(Fore.YELLOW + 'Enter a drive or a path if not in window:')
        main(path, 0)
    if str(service) == '4':
        print(Fore.MAGENTA + 'Timer Value:'+str(delay_seconds)+" seconds")
        print(Fore.MAGENTA + "Main Path:"+str(main_path))
        value = input(Fore.YELLOW + 'Do you want to change the default settings(Y/N):')
        if str(value) == 'Y' or str(value) == 'y':
            delay_seconds = int(86400 * int(input(Fore.YELLOW + 'Enter a new timer value (Days):')))
            main_path = input(Fore.YELLOW + 'Enter a new main path:')
        timer()
