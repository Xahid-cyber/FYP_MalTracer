#!/usr/bin/python3

import requests
import os
import re
import hashlib
import sys
import math
import getpass
import json
from datetime import date
from utils.helpers import err_exit, user_confirm

try:
    import sqlite3
except:
    err_exit("Module: >sqlite3< not found.")

# Module for progressbar
try:
    from tqdm import tqdm
except:
    err_exit("Module: >tqdm< not found.")

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich.panel import Panel
except:
    err_exit("Error: >rich< module not found.")

try:
    from colorama import Fore, Style
except:
    err_exit("Error: >colorama< module not found.")

# Parsing date
today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Colors
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering username
username = getpass.getuser() # NOTE: If you run program as sudo your username will be "root" !!

# Gathering Qu1cksc0pe path variable
sc0pe_path = open(os.path.join(os.path.expanduser("~"), ".qu1cksc0pe_path"), "r").read().strip()

# User home detection and compatibility
homeD = os.path.expanduser("~")
path_seperator = "/"
setup_scr = "setup.sh"
if sys.platform == "win32":
    path_seperator = "\\"
    setup_scr = "setup.ps1"

# Directory checking
if os.path.exists(f"{homeD}{path_seperator}sc0pe_Base"):
    pass
else:
    os.system(f"mkdir {homeD}{path_seperator}sc0pe_Base")

# Configurating installation directory
install_dir = f"{homeD}{path_seperator}sc0pe_Base"

def Downloader():
    local_database = f"{install_dir}{path_seperator}HashDB"
    dbUrl = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
    req = requests.get(dbUrl, stream=True)
    total_size = int(req.headers.get('content-length', 0))
    block_size = 1024
    wrote = 0
    print(f"\n{infoS} Downloading signature database please wait...")
    try:
        with open(local_database, 'wb') as ff:
            for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                wrote = wrote + len(data)
                ff.write(data)
        print(f"\n{infoS} Now you are ready to go :)")
        sys.exit(0)
    except:
        sys.exit(0)

def DatabaseCheck():
    if os.path.isfile(f"{install_dir}{path_seperator}HashDB") == False:
        print("[blink bold white on red]Local signature database not found!!")
        if user_confirm(f"{green}=>{white} Would you like to download it [Y/n]?: "):
            Downloader()
        else:
            err_exit("\n[bold white on red]Without local database [blink]--hashscan[/blink] [white]will not work!!\n")

# Hashing with md5
def GetHash(targetFile):
    hashMd5 = hashlib.md5()
    try:
        with open(targetFile, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashMd5.update(chunk)
    except:
        pass
    return hashMd5.hexdigest()

# Accessing hash database content
if os.path.exists(f"{install_dir}{path_seperator}HashDB"):
    hashbase = sqlite3.connect(f"{install_dir}{path_seperator}HashDB")
    dbcursor = hashbase.cursor()
else:
    DatabaseCheck()

# Check for if database is up to date
def UpToDate():
    print("[bold]Checking for database state...")
    try:
        dbs = requests.get("https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/README.md")
        database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()
        match = re.findall(str(len(database_content)), str(dbs.text))
        if match != []:
            print("[bold]Database State: [bold green]Up to date.\n")
        else:
            print("[bold]Database State: [bold red]Outdated.")
            print("[bold magenta]>>>[bold white] You should use [bold green]'--db_update' [bold white]argument to update your malware hash database.\n")
    except:
        print("[bold white on red]An error occured while connecting to Github!!")

# Updating database
def DatabaseUpdate():
    if os.path.exists(install_dir):
        if os.path.exists(f"{install_dir}{path_seperator}HashDB"):
            print("[bold magenta]>>>[bold white] Removing old database...")
            if sys.platform == "win32":
                os.system(f"powershell -c \"del {install_dir}{path_seperator}HashDB -Force -Recurse\"")
            else:
                os.system(f"rm -rf {install_dir}{path_seperator}HashDB")
            Downloader()
            print("[bold green]>>>[bold white] New database has successfully downloaded.")
        else:
            print(f"{infoS} Looks like you don\'t have any hash database. Downloading it for you...")
            Downloader()
            print("[bold green]>>>[bold white] New database has successfully downloaded.")
    else:
        print(f"{errorS} Error: [bold green]{install_dir}[white] directory not found!")
        print(f"[bold magenta]>>>[white] Make sure [bold green]{setup_scr}[white] script is worked successfully!")
        print(f"[bold magenta]>>>[white] If you don\'t want to execute [bold green]{setup_scr}[white] then try this: [bold green]python qu1cksc0pe.py --file your_sample --hashscan[white]")

# Handling single scans
def NormalScan():
    # Hashing
    targetHash = GetHash(targetFile)

    # Creating answer table
    answTable = Table()
    answTable.add_column("[bold green]Hash", justify="center")
    answTable.add_column("[bold green]Name", justify="center")

    # Total hashes
    database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()

    # Printing informations
    print(f"[bold cyan]>>>[white] Total Hashes: [bold green]{len(database_content)}")
    print(f"[bold cyan]>>>[white] File Name: [bold green]{targetFile}")
    print(f"[bold cyan]>>>[white] Target Hash: [bold green]{targetHash}")

    # Finding target hash in the database_content
    db_answer = dbcursor.execute(f"SELECT * FROM HashDB where hash='{targetHash}'").fetchall()
    if db_answer != []:
        answTable.add_row(f"[bold red]{db_answer[0][0]}", f"[bold red]{db_answer[0][1]}")
        print(answTable)
    else:
        print("\n[bold white on red]Target hash is not in our database!!")
        print("[bold magenta]>>>[bold white] Try [green]--analyze[white] and [green]--vtFile[white] instead.\n")
    hashbase.close()

# Handling multiple scans
# ... (imports and initial setup remain the same)

def MultipleScan():
    # Creating application layout - Simplified to remove the progress section
    program_layout = Layout(name="RootLayout")
    program_layout.split_column(
        Layout(name="Top"),
        Layout(name="Bottom")
    )
    # The bottom is now split simply between Info and Live Status
    program_layout["Bottom"].split_row(
        Layout(name="bottom_left"),
        Layout(name="bottom_right")
    )

    # Handling folders
    if os.path.isdir(targetFile) == True:
        print("[bold red]>>>[bold white] Qu1cksc0pe gathering all files... [bold blink]Please wait...")
        scanfiles = Table()
        scanfiles.add_column("[bold green]Name", justify="center")
        scanfiles.add_column("[bold green]Count", justify="center")
        
        scan_count = 0
        file_names = []
        for root, d_names, f_names in os.walk(targetFile):
            for ff in f_names:
                file_names.append(os.path.join(root, ff))
                scan_count += 1
                if len(scanfiles.columns[0]._cells) < 13:
                    scanfiles.add_row(f"{os.path.join(root, ff)}", str(scan_count))

        filNum = len(file_names)
        database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()

        # Summary table for detections
        mulansTable = Table()
        mulansTable.add_column("[bold green]File Names", justify="center")
        mulansTable.add_column("[bold green]Hash", justify="center")
        mulansTable.add_column("[bold green]Name", justify="center")

        # Top Panel
        upper_grid = Table.grid()
        upper_grid.add_row(
            Panel(scanfiles, border_style="bold cyan", title="Files To Scan"),
            Panel(mulansTable, border_style="bold red", title="Malicious Files")
        )
        program_layout["Top"].update(Panel(upper_grid, border_style="bold blue", title="Qu1cksc0pe Hashscan"))

        # Bottom Panels
        program_layout["bottom_left"].update(
            Panel(
                Text(f"Date: {dformat}\nTarget Directory: {targetFile}\nDatabase Length: {len(database_content)}\nTotal Files: {scan_count}"), 
                border_style="bold magenta", title="General Information"
            )
        )
        
        program_layout["bottom_right"].update(
            Panel(
                Text("Waiting for scan to start..."),
                border_style="bold cyan", title="Live Scan Status"
            )
        )

        # Scan zone - Progress logic removed from the UI update
        with Live(program_layout, refresh_per_second=4):
            for tf in range(filNum):
                if file_names[tf] != '':
                    scanme = f"{file_names[tf]}"
                    targetHash = GetHash(scanme)
                    splitted = os.path.split(scanme)[1]

                    db_answers = dbcursor.execute(f"SELECT * FROM HashDB where hash='{targetHash}'").fetchall()
                    if db_answers != []:
                        if len(mulansTable.columns[0]._cells) < 11:
                            mulansTable.add_row(f"{splitted}", f"{db_answers[0][0]}", f"{db_answers[0][1]}")
                        else:
                            ans_ind = len(mulansTable.columns[0]._cells)
                            mulansTable.columns[0]._cells[ans_ind-1] = Text(f"{splitted}")
                            mulansTable.columns[1]._cells[ans_ind-1] = Text(f"{db_answers[0][0]}")
                            mulansTable.columns[2]._cells[ans_ind-1] = Text(f"{db_answers[0][1]}")
                    
                    # Update Live Scan Status (Progress bar removed)
                    program_layout["bottom_right"].update(
                        Panel(
                            Text(f"Scanning: {tf+1}/{filNum}\nFile: {splitted}\nHash: {targetHash}"),
                            border_style="bold cyan", title="Live Scan Status"
                        )
                    )
        hashbase.close()
        # ADD THIS HERE
    print("\n" + "="*50)
    print(f"[bold green]>>> HASH SCAN COMPLETE")
    print(f"[bold cyan]Total Files Scanned: [white]{filNum}")
    
    # If the table has rows (malicious files found), print it one last time
    if len(mulansTable.columns[0]._cells) > 0:
        print(f"\n[bold red]DETECTION SUMMARY:")
        print(mulansTable)
    else:
        print(f"\n[bold green][+] No malicious hashes were found in this directory.")
    print("="*50 + "\n")

    

if __name__ == '__main__':
    # File handling
    if str(sys.argv[1]) == '--db_update':
        DatabaseUpdate()
    else:
        targetFile = sys.argv[1]

    if str(sys.argv[2]) == '--normal':
        UpToDate()
        NormalScan()
    else:
        UpToDate()
        MultipleScan()