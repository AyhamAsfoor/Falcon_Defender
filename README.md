# Falcon Defender
[![License](https://img.shields.io/github/license/AyhamAsfoor/Anti_Virus_V1.4?logo=Github)](https://github.com/AyhamAsfoor/Anti_Virus_V1.4/blob/main/LICENSE)
[![GitHub top language](https://img.shields.io/github/languages/top/AyhamAsfoor/Anti_Virus_V1.4?logo=github)](https://github.com/AyhamAsfoor/Anti_Virus_V1.4)
[![Code Size](https://img.shields.io/github/languages/code-size/AyhamAsfoor/Falcon_Defender?logo=github)](https://github.com/AyhamAsfoor/Falcon_Defender)
[![GitHub issues](https://img.shields.io/github/issues/AyhamAsfoor/Anti_Virus_V1.4?logo=github)](https://github.com/AyhamAsfoor/Anti_Virus_V1.4/issues)
```py
 ______    _                   _____        __               _           
|  ____|  | |                 |  __ \      / _|             | |          
| |__ __ _| | ___ ___  _ __   | |  | | ___| |_ ___ _ __   __| | ___ _ __ 
|  __/ _` | |/ __/ _ \| '_ \  | |  | |/ _ \  _/ _ \ '_ \ / _` |/ _ \ '__|
| | | (_| | | (_| (_) | | | | | |__| |  __/ ||  __/ | | | (_| |  __/ |   
|_|  \__,_|_|\___\___/|_| |_| |_____/ \___|_| \___|_| |_|\__,_|\___|_|   
```
## Overview
This project is a robust antivirus software implemented in Python. It leverages YARA rules to detect malicious files within the system and provides options to quarantine, delete, or move them to a specified folder.

## What is this project?
This project is a comprehensive antivirus tool designed to scan directories, files, and drives for potential threats using YARA signatures. It offers essential functionalities such as quarantine and deletion of identified malicious files, all through a simple command-line interface.

## Key Features
- YARA Rule-Based Scanning: Utilizes custom YARA rules to identify malicious files based on defined signatures.
- Quarantine Functionality: Moves detected threats to a designated quarantine folder for further analysis or removal.
- Command-Line Interface: Provides an intuitive CLI for users to initiate scans and manage detected threats.
- Periodic Scanning: Supports automated periodic scans based on user-configurable settings.
  
## How to Use
### 1) Installation:
- Ensure Python is installed on your computer.
- Install required dependencies using ```pip install -r requirements.txt ``` 

### 2) Execution:
Follow the command-line prompts to select scanning options and directories.

### 3) Configuration:
Customize periodic scan settings by modifying variables in the main script.
## Dependencies
- YARA: For malware signature detection in files.
- colorama: For adding colors to the command-line interface.
- progressbar: For displaying progress bars during the scanning process.
- PyFiglet: For rendering stylized text in large fonts.
## Credits
- YARA: Malware detection engine using custom rules.
- colorama: Library for terminal text coloring.
- progressbar: Tool for displaying progress bars in the console.
- PyFiglet: Library for generating ASCII art text.

## Cloning the Repository
To clone this repository and run the antivirus software locally, follow these steps:
1. Open a terminal or command prompt on your computer.
2. Navigate to the directory where you want to clone the repository.
3. Use the following command to clone the repository:

```py
https://github.com/AyhamAsfoor/Falcon_Defender/blob/main/Falcon_Defender.py
```

Once the repository is cloned, navigate into the project directory:
```
cd <repalce_project_directory>
```
> [!TIP]
> Follow the instructions in the How to Use section of the README to install dependencies and execute the antivirus software.

>[!IMPORTANT]
> If you have any issues, please don't be shy to get in touch with me.

## Flowchart Structure
```mermaid
graph TD;
   Falcon_Defender_Project-->Service_1_Browse;
   Service_1_Browse-->Services;
   Falcon_Defender_Project-->Service_2_Path;
   Falcon_Defender_Project-->Service_3_Drive;
   Service_3_Drive-->Get_Drive;
   Falcon_Defender_Project-->Service_4_Periodic;
   Service_4_Periodic-->Initial_Main;
   Initial_Main-->Timer;
   Timer-->Initial_Main;
   Timer-->Main;
   Services-->|Directory| Main;
   Services-->|File| Main;
   Service_2_Path-->Main;
   Get_Drive-->Main;
   Main-->Get_OS_Type;
   Get_OS_Type-->Get_Rule_Dir;
   Get_Rule_Dir-->MK_Dict;
   Data_Base_of_Signature-->MK_Dict;
   MK_Dict-->Parse_Yara_File;
   Parse_Yara_File-->|Directory| DIR_Search;
   Parse_Yara_File-->|File| Yara_Sig_Check;
   DIR_Search-->Write_File;
   Yara_Sig_Check-->quarantine_file;
   quarantine_file-->|Directory| Write_File;
   Yara_Sig_Check-->|If the file is not malicious| False;
   quarantine_file-->|If the file is malicious| True;
   Write_File-->Report_txt[Report.txt];
   Write_File-->Result[Result];

   style Falcon_Defender_Project fill:#25940f;
   style Service_1_Browse fill:#010f76;
   style Service_2_Path fill:#010f76;
   style Service_3_Drive fill:#010f76;
   style Service_4_Periodic fill:#010f76;
   style Data_Base_of_Signature fill:#f58200;
   style Report_txt fill:#ac270b;
   style Result fill:#ac270b;
   style True fill:#ac270b;
   style False fill:#0b74ac;
```

## License
This project is licensed under the Apache License 2.0.
You can find the full text of the license in the LICENSE file.

### Support Us 🥤:
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-donate-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white)](https://www.buymeacoffee.com/ayhamasfoor)
