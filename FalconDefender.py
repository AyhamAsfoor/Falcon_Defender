import sys
import os
import time
import yara
import warnings
import pyfiglet
import threading
import progressbar
import smtplib
from colorama import Fore, init
from tkinter import filedialog
from terminaltables import SingleTable
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


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

    # TODO: We want to look for a solution to the problem of not being able to scan the file
    #  due to special characters or permissions

    except yara.Error:  # as yara_error
        pass
        # print(f"YARA error: {yara_error}") -- bug need to be fixed -- 10/30/2024
    except PermissionError:  # as perm_error
        pass
        # print(f"Permission error: {perm_error}") Handle permission -- bug need to be fixed -- 10/30/2024
    except FileNotFoundError:  # as fnf_error
        # print(f"File not found error: {fnf_error}") Handle file not found -- bug need to be fixed -- 10/30/2024
        pass
    except Exception:  # as unexpected
        # print(f"An unexpected error occurred: {unexpected}") -- bug need to be fixed -- 10/30/2024
        pass


def quarantine_file(file_path, quarantine_folder):
    try:
        new_path = os.path.join(quarantine_folder, os.path.basename(file_path))
        os.rename(file_path, new_path)
        print(f"{Fore.RED}File {file_path} has been quarantined to {quarantine_folder}")
    except Exception as e:
        print(f"{Fore.RED}Error quarantining file: {str(e)}")


def dir_search(user_dir, rule_dict1):
    global number_of_files, malicious_files, scanned_time
    hit_files = []
    timer_start = time.time()
    file_number = 0
    delete = str(input(f"{Fore.RED}Are you sure you want to delete a file? (y/n):"))
    rules = yara.compile(filepaths=rule_dict1)

    print(Fore.RESET + "Gathering your files...")
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
             f"All malicious files that were identified below\n" \
             f"=========================\n"
    write_file("Scan_Reports.txt", banner)
    bar = progressbar.ProgressBar(maxval=file_number, widgets=[progressbar.Bar(
        f'{Fore.GREEN}=', f'{Fore.CYAN}[', f'{Fore.CYAN}]'), ' ',
        progressbar.Percentage()])
    bar.start()
    for root, dirs, files in os.walk(user_dir, topdown=True):
        for name in files:

            file_path = os.path.realpath(os.path.join(root, name))
            scanned_file = (yara_sig_check(file_path, rules))

            if scanned_file is not None and hit_files.__contains__(scanned_file) == False:
                scanned_file = os.path.splitext(os.path.basename(scanned_file))[0]
                hit_files.append(scanned_file)
                if delete in ["Y", "Ya", "y", "yes", "YES"]:
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

    number_of_files = str(file_number)
    malicious_files = str(len(hit_files))
    scanned_time = time.strftime('%H:%M:%S')

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
        time.sleep(1)
        return "windows"
    if os_sys.startswith("linux"):
        print("Platform detected: Linux")
        print("Executing commands... ")
        time.sleep(1)
        return "linux"
    if os_sys == "darwin":
        print("Platform detected: Mac")
        print("Executing commands... ")
        time.sleep(1)
        return "mac"
    if os_sys == "cygwin":
        print("Platform detected: Windows/Cygwin")
        print("Executing commands... ")
        time.sleep(1)
        return "cygwin"
    else:
        print(Fore.RED + "Platform not detected, exiting...")
        sys.exit()


def get_rule_dir(os_type):
    if os_type == "windows":
        rule_path = r"rule_files/rules.yar"
        return rule_path
    if os_type == "mac":
        rule_path = r"Antivirus/rules.yar"
        return rule_path
    if os_type.startswith("linux"):
        rule_path = r"Antivirus/rules.yar"
        return rule_path
    return None


def main(dir_name, type_string):
    global rule_dict
    print(Fore.RESET + "Attempting to detect your system configuration... ")
    time.sleep(3)
    os_main = get_os_type()
    if type_string == 0:
        if os_main in ["windows", "mac", "linux"]:
            rule_path = get_rule_dir(os_main)
            if rule_path:
                rule_dict = mk_dict(rule_path)
                dir_search(dir_name, rule_dict)
        else:
            print(Fore.RED + "Unsupported OS :(")
    elif type_string == 1:
        if os_main in ["windows", "mac", "linux"]:
            rule_path = get_rule_dir(os_main)
            if rule_path:
                rule_dict = mk_dict(rule_path)
                rules = yara.compile(filepaths=rule_dict)
                scanned_file = yara_sig_check(dir_name, rules)
                if scanned_file:
                    print(f"{Fore.RED} File was hit: {scanned_file} is a malicious file.")
                else:
                    print(Fore.GREEN + "The file you scanned is NOT a malicious file.")
        else:
            print(Fore.RED + "Unsupported OS :(")


def services(dir_file):
    if dir_file in ["File", "file", "FILE"]:
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
        anti_virus_mail(scan_date=scanned_time, num_files=number_of_files, num_threats=malicious_files,
                        scanned_path=main_path,
                        recommendations="Keep your software updated and avoid suspicious websites.")
        print("Done")
        timer()

    global delay_seconds
    timer_value = threading.Timer(delay_seconds, initial_main)
    timer_value.start()


def anti_virus_mail(scan_date, num_files, num_threats, scanned_path, recommendations):
    password = "pqwz wlvj icrw cuap"
    msg = MIMEMultipart()
    msg['From'] = "ayhamasfoor1@gmail.com"
    msg['To'] = f"{main_email}"
    msg['Subject'] = "Update on Your Latest Periodic Scan"
    body = f"""
        Dear Ayham,

        Greetings,

        We are pleased to inform you that we have completed the latest periodic scan on your device using our antivirus
        software. This routine scan aims to ensure your device is protected against security threats and is performing
        optimally.

        Summary of the Periodic Scan:
        - Date: {scan_date}
        - Number of files scanned: {num_files}
        - Threats detected: {num_threats}
        - Path: {scanned_path}

        Recommendations:
        {recommendations}

        We encourage you to continue with regular scans and keep your antivirus software updated to maintain the highest
        level of protection.

        If you have any questions or need further assistance,
        please do not hesitate to contact us at Ayhamasfoor1@ieee.org.
        Thank you for using FalconDefender V1.5. We are here to ensure the security of your device
        and the safety of your data.

        Best regards,

        Customer Support Team
        [FalconDefender V1.5]
        """
    try:
        msg.attach(MIMEText(body, 'plain'))

        filename = "Scan_Reports.txt"

        attachment = open(filename, "rb")

        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= {filename}")

        msg.attach(part)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login("ayhamasfoor1@gmail.com", password)
        text = msg.as_string()
        server.sendmail("ayhamasfoor1@gmail.com", "ayhamasfoor1@ieee.org", text)
        server.quit()
    except smtplib.SMTPAuthenticationError:
        print(Fore.RED + "Error: Authentication failed. Please check your username and password.")
    except smtplib.SMTPConnectError:
        print(Fore.RED + "Error: Unable to connect to the SMTP server. Please check the server address, port and Wifi.")
    except smtplib.SMTPException as e:
        print(Fore.RED + f"SMTP error occurred: {e}")
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: Sending Failed. Please check the server address"
                         f",port and your connection:ERR NO: {e}")


if __name__ == "__main__":
    delay_seconds = 10
    rule_dict = 0
    main_path = 'test'
    main_email = "ayhamasfoor1@ieee.org"
    number_of_files = ""
    malicious_files = ""
    scanned_time = ""
    path = ""
    type_ser = ""
    done = True
    data = [
        ['Tool Name', 'Description'],
        ['Real-time Scan', 'Scans files in real-time to detect threats.'],
        ['Deep Scan', 'Performs a comprehensive system scan for malware.'],
        ['Log Analysis', 'Analyzes system logs for suspicious activities.'],
        ['Quarantine', 'Isolates detected threats to prevent harm.'],
        ['Update Definitions', 'Keeps antivirus definitions up to date.'],
    ]

    warnings.filterwarnings("ignore", category=RuntimeWarning)

    init(autoreset=True)
    custom_fig = pyfiglet.Figlet(font='big')
    ascii_art = custom_fig.renderText('Falcon Defender')
    colored_ascii_art = f'{Fore.BLUE}{ascii_art}'
    print(colored_ascii_art)
    table = SingleTable(data)
    table.title = 'FalconDefender V1.5'
    print(Fore.MAGENTA + table.table + "\n\n")
    print(Fore.YELLOW + "Welcome to FalconDefender Anti-Virus. Enter '--help' for a list of commands.")
    print(Fore.BLUE + "[1] Select a specific Directory/File by Browse.\n"
                      "[2] Select a specific Directory/File by Path.\n"
                      "[3] Select a Drives to scan.\n"
                      "[4] Default settings for Periodic scan.\n"
                      "[5] Exit.\n")
    while done:
        command = input(Fore.YELLOW + "Enter command >> ").strip().lower()

        if command == "--help":
            print(Fore.LIGHTYELLOW_EX + "Available commands:")
            print(Fore.LIGHTGREEN_EX + "  scandir                           - Scan a specific directory")
            print(Fore.LIGHTGREEN_EX + "  scanfile                          - Scan a specific file")
            print(Fore.LIGHTGREEN_EX + "  scan -d                           - Scan the specific file")
            print(Fore.LIGHTGREEN_EX + "  scan -p <directory_or_file>       - Scan a directory for files of a specific"
                                       " type (e.g., .exe)")
            print(Fore.LIGHTGREEN_EX + "  scan -t <day>                     - Run a Periodic scan")
            print(Fore.LIGHTGREEN_EX + "  exit                              - Exit the program")

        elif str(command) in ['scandir', 'scanfile']:
            if command.startswith("scandir"):
                path, type_ser = services('dir')
                while True:
                    if path == "":
                        print(Fore.RED + "Error, Pleas reselect a path.")
                        path, type_ser = services('dir')
                    else:
                        break

            if command.startswith("scanfile"):
                path, type_ser = services('file')
                while True:
                    if path == "":
                        print(Fore.RED + "Error, Pleas reselect a path.")
                        path, type_ser = services('file')
                    else:
                        break

            main(path, type_ser)
        elif str(command) == 'scan -p':
            path = input(Fore.YELLOW + 'input a path would to scan >> ')
            while True:
                if path == "":
                    print(Fore.RED + "Error, Pleas reselect a path.")
                    path = input(Fore.YELLOW + 'input a path would to scan >> ')
                else:
                    break
            if not os.path.isfile(path):
                type_ser = 0
            else:
                type_ser = 1
            main(path, type_ser)
        elif str(command) == 'scan -d':
            drive_names = get_drive()
            print(Fore.YELLOW + 'Your Drives :')
            for drive in drive_names:
                print(Fore.MAGENTA + drive)
            path = input(Fore.YELLOW + 'Enter a drive or a path if not in window >> ')
            main(path, 0)
        elif str(command) == 'scan -t':
            print(Fore.MAGENTA + 'Timer Value:' + str(delay_seconds) + " seconds")
            print(Fore.MAGENTA + "Main Path:" + str(main_path))
            print(Fore.MAGENTA + "Main Email:" + str(main_email))
            value = input(Fore.YELLOW + 'Do you want to change the default settings(Y/N):')
            if str(value) == 'Y' or str(value) == 'y':
                delay_seconds = int(86400 * int(input(Fore.YELLOW + 'Enter a new timer value (Days) >> ')))
                main_path = input(Fore.YELLOW + 'Enter a new main path >> ')
                main_email = input(Fore.YELLOW + 'Enter a new main Email >> ')
            timer()
        elif str(command) == 'exit':
            print(Fore.MAGENTA + "Bye and be secure with Falcon ;)")
            time.sleep(5)
            done = False

        else:
            print(Fore.RED + "ERR: Invalid command" + Fore.RESET)
