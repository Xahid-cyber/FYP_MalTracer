#!/usr/bin/python3


# module checking
try:
    import os
    import sys
    import subprocess
    import argparse
    import getpass
    import configparser
    import shutil
    import warnings
    import time
except Exception as e:
    print(f"Missing modules detected!: {e}")
    sys.exit(1)

# Define home directory and path separator for cross-platform compatibility
homeD = os.path.expanduser("~")
path_seperator = "\\" if os.name == "nt" else "/"
infoC = "[bold cyan][[bold red]*[bold cyan]][white]"
foundS = "[bold cyan][[bold red]+[bold cyan]][white]"
# Check python version
if sys.version_info[0] == 2:
    print(f"{errorS} Looks like you are using Python 2. But we need Python 3!")
    sys.exit(1)

# When invoked via `sudo`, root's Python env lacks the original user's pip packages.
# Add that user's site-packages so all dependencies remain accessible.
_sudo_user = os.environ.get("SUDO_USER")
if _sudo_user and os.getuid() == 0:
    _pyver     = f"python{sys.version_info.major}.{sys.version_info.minor}"
    _user_home = os.path.expanduser(f"~{_sudo_user}")
    _user_site = os.path.join(_user_home, ".local", "lib", _pyver, "site-packages")
    if os.path.isdir(_user_site) and _user_site not in sys.path:
        sys.path.insert(0, _user_site)
    del _user_home, _user_site, _pyver
del _sudo_user

# Testing rich existence
try:
    from rich import print
except ModuleNotFoundError:
    print("Error: >rich< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

# Testing puremagic existence
try:
    import puremagic as pr
except ModuleNotFoundError:
    print("Error: >puremagic< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Style
except ModuleNotFoundError:
    print("Error: >colorama< module not found. Run: pip3 install -r requirements.txt")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Gathering username
username = getpass.getuser()

# Always use the same interpreter that is running this script
py_binary = sys.executable

# Detect path separator based on OS
path_seperator = "\\" if sys.platform == "win32" else "/"

# SIMPLE PATH DETECTION:
# We just assume the script is running from its current directory.
sc0pe_path = os.getcwd()

# Utility functions
from Modules.utils.helpers import err_exit

# Define the Module path clearly
MODULE_PREFIX = f"{sc0pe_path}{path_seperator}Modules{path_seperator}"

def execute_module(target, path=MODULE_PREFIX, invoker=py_binary):
    # Split target into script name and arguments
    parts  = target.split(" ", 1)
    script = parts[0]
    extra  = f" {parts[1]}" if len(parts) > 1 else ""
    
    # Execute the module using the same python interpreter
    os.system(f'{invoker} "{path}{script}"{extra}')

#import Modules.banners # show a banner

# Argument crating, parsing and handling
ARG_NAMES_TO_KWARG_OPTS = {
    "file": {"help": "Specify a file to scan or analyze."},
    "folder": {"help": "Specify a folder to scan or analyze."},
    "analyze": {"help": "Analyze target file.", "action": "store_true"},
    "archive": {"help": "Analyze archive files.", "action": "store_true"},
    "db_update": {"help": "Update malware hash database.", "action": "store_true"},
    "docs": {"help": "Analyze document files.", "action": "store_true"},
    "domain": {"help": "Extract URLs and IP addresses from file.", "action": "store_true"},
    "hashscan": {"help": "Scan target file's hash in local database.", "action": "store_true"},
    "key_init": {"help": "Enter your VirusTotal API key.", "action": "store_true"},
    "lang": {"help": "Detect programming language.", "action": "store_true"},
    "packer": {"help": "Check if your file is packed with common packers.", "action": "store_true"},
    "sigcheck": {"help": "Scan file signatures in target file.", "action": "store_true"},
    "vtFile": {"help": "Scan your file with VirusTotal API.", "action": "store_true"},
    "mitre": {"help": "Perform only MITRE ATT&CK mapping.", "action": "store_true"},
    "json": {"help": "Output results in JSON format for automation.", "action": "store_true"}, # <--- ADD THIS
    "ui": {"help": "Launch MalTracer backend API.", "action": "store_true"},
    "report": {"help": "Export analysis reports into a file (JSON Format for now).", "action": "store_true"},
    "behavioral": {"help": "Run AI-based EMBER 2024 behavioral ML analysis.", "action": "store_true"}
}

parser = argparse.ArgumentParser()
for arg_name, cfg in ARG_NAMES_TO_KWARG_OPTS.items():
    cfg["required"] = cfg.get("required", False)
    parser.add_argument("--" + arg_name, **cfg)
args = parser.parse_args()
def _latest_report_path():
    try:
        candidates = [f for f in os.listdir(".") if f.startswith("sc0pe_") and f.endswith("_report.json")]
    except Exception:
        return None
    if not candidates:
        return None
    candidates = [os.path.abspath(c) for c in candidates if os.path.exists(c)]
    if not candidates:
        return None
    return max(candidates, key=lambda p: os.path.getmtime(p))
def launch_web_ui():
    web_app_path = os.path.join(sc0pe_path, "Modules", "web_app.py")
    if not os.path.exists(web_app_path):
        err_exit(f"{errorS} Backend API entrypoint not found: {web_app_path}")
    print(f"{infoS} Launching [bold green]MalTracer Backend API[white]...")
    try:
        ui_proc = subprocess.run([sys.executable, web_app_path], check=False)
    except KeyboardInterrupt:
        print("\n[bold white on red]MalTracer Backend API terminated by user.\n")
        return
    if ui_proc.returncode != 0:
        err_exit(
            f"{errorS} Failed to launch MalTracer Backend API. Make sure dependencies are installed "
            f"(e.g. [bold green]pip install -r requirements.txt[white]).",
            arg_override=ui_proc.returncode,
        )




# Basic analyzer function that handles single and multiple scans
def BasicAnalyzer(analyzeFile):
    print(f"{infoS} Analyzing: [bold green]{analyzeFile}[white]")
    fileType = str(pr.magic_file(analyzeFile))
    lower_ext = os.path.splitext(analyzeFile)[1].lower()
    # Windows Analysis
    if "Windows Executable" in fileType or ".msi" in fileType or ".dll" in fileType or ".exe" in fileType:
        print(f"{infoS} Target OS: [bold green]Windows[white]\n")
        if args.report:
            execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" True True")
        else:
            execute_module(f"windows_static_analyzer.py \"{analyzeFile}\" False True")
        
# VBScript/VBA family analysis
    elif lower_ext in (".vbs", ".vbe", ".vba", ".vb", ".bas", ".cls", ".frm"):
        print(f"{infoS} Performing [bold green]VBScript/VBA[white] analysis...\n")
        if args.report:
            execute_module(f"document_analyzer.py \"{analyzeFile}\" True")
        else:
            execute_module(f"document_analyzer.py \"{analyzeFile}\" False")
    else:
        err_exit("\n[bold white on red]File type not supported. Make sure you are analyze executable files or document files.\n[bold]>>> If you want to scan document files try [bold green][i]--docs[/i] [white]argument.")

# Main function
def Malsecure():
    if args.ui:
        launch_web_ui()
        return


    # Getting all strings from the file if the target file exists.
    if args.file:
        if os.path.exists(args.file):
            # Before doing something we need to check file size
            file_size = os.path.getsize(args.file)
            if file_size < 52428800: # If given file smaller than 100MB
                if not shutil.which("strings"):
                    err_exit("[bold white on red][blink]strings[/blink] command not found. You need to install it.")
            else:
                print(f"{infoS} Whoa!! Looks like we have a large file here.")
                if args.analyze:
                    choice = str(input(f"\n{infoC} Do you want to analyze this file anyway [y/N]?: "))
                    if choice == "Y" or choice == "y":
                        BasicAnalyzer(analyzeFile=args.file)
                        sys.exit(0)

                if args.archive:
                    # Because why not!
                    print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
                    if args.report:
                        execute_module(f"archiveAnalyzer.py \"{args.file}\" True")
                    else:
                        execute_module(f"archiveAnalyzer.py \"{args.file}\" False")
                    
                    sys.exit(0)

                # Check for embedded executables by default!
                if not args.sigcheck:
                    print(f"{infoS} Executing [bold green]SignatureAnalyzer[white] module...")
                    execute_module(f"sigChecker.py \"{args.file}\"")
                    sys.exit(0)
        else:
            err_exit("[bold white on red]Target file not found!\n")

    # Analyze the target file
    if args.analyze:
        # Handling --file argument
        if args.file is not None:
            BasicAnalyzer(analyzeFile=args.file)
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--analyze[/blink] argument is not supported for folder analyzing!\n")

    # Analyze archive files
    if args.archive:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            if args.report:
                execute_module(f"archiveAnalyzer.py \"{args.file}\" True")
            else:
                execute_module(f"archiveAnalyzer.py \"{args.file}\" False")
            
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Analyze document files
    if args.docs:
        # Handling --file argument
        if args.file is not None:
            print(f"{infoS} Analyzing: [bold green]{args.file}[white]")
            if args.report:
                execute_module(f"document_analyzer.py \"{args.file}\" True")
            else:
                execute_module(f"document_analyzer.py \"{args.file}\" False")
            
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--docs[/blink] argument is not supported for folder analyzing!\n")

    # Hash Scanning
    if args.hashscan:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"hashScanner.py \"{args.file}\" --normal")
        # Handling --folder argument
        if args.folder is not None:
            execute_module(f"hashScanner.py {args.folder} --multiscan")
    # File signature scanner
    if args.sigcheck:
        # Handling --file argument
        if args.file is not None:
            execute_module(f"sigChecker.py \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--sigcheck[/blink] argument is not supported for folder analyzing!\n")

    

    # Language detection
    # Language detection
    if args.lang:
    # Handling --file argument
        if args.file is not None:
            if args.report:
            # Removed AI boolean flag
                execute_module(f"languageDetect.py \"{args.file}\" True")
            else:
            # Removed AI boolean flag
                execute_module(f"languageDetect.py \"{args.file}\" False")
            
    # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--lang[/blink] argument is not supported for folder analyzing!\n")
    
    if args.mitre:
        if args.file is not None:
            from Modules.mitre_mapper import mitre_mapper
            mitre_json = os.path.join(sc0pe_path, "Systems", "Windows", "mitre_for_windows.json")
            mitre_mapper(args.file, mitre_json)
        if args.folder is not None:
            err_exit("--mitre is not supported for folder analysis.\n")


    if args.behavioral:
        if args.file is not None:
            report_flag = "True" if args.report else "False"
        # Add "../" to exit the Modules folder and find the script in root
            execute_module(f"..{path_seperator}MalSecure_behavioral.py --file \"{args.file}\" {report_flag}")
        
        

        
        
    # VT File scanner
    if args.vtFile:
        # Handling --file argument
        if args.file is not None:
            # if there is no key quit
            try:
                directory = f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt"
                apik = open(directory, "r").read().split("\n")
            except:
                err_exit("[bold white on red]Use [blink]--key_init[/blink] to enter your key!\n")
            # if key is not valid quit
            if apik[0] == '' or apik[0] is None or len(apik[0]) != 64:
                err_exit("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a]\n")
            else:
                execute_module(f"VTwrapper.py {apik[0]} \"{args.file}\"")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red]If you want to get banned from VirusTotal then do that :).\n")

    # packer detection
    if args.packer:
    # Handling --file argument
        if args.file is not None:
            if args.report:
            # Removed AI part
                execute_module(f"packerAnalyzer.py --single \"{args.file}\" True")
            else:
            # Removed AI part
                execute_module(f"packerAnalyzer.py --single \"{args.file}\" False")
            
    # Handling --folder argument
        if args.folder is not None:
            if args.report:
            # Removed AI part
                execute_module(f"packerAnalyzer.py --multiscan {args.folder} True")
            else:
            # Removed AI part
                execute_module(f"packerAnalyzer.py --multiscan {args.folder} False")

    # domain extraction
    if args.domain:
        # Handling --file argument
        if args.file is not None:
            if args.report:
                execute_module(f"domainCatcher.py \"{args.file}\" True")
            else:
                execute_module(f"domainCatcher.py \"{args.file}\" False")
        # Handling --folder argument
        if args.folder is not None:
            err_exit("[bold white on red][blink]--domain[/blink] argument is not supported for folder analyzing!\n")

    

    # Database update
    if args.db_update:
        execute_module(f"hashScanner.py --db_update")

    # entering VT API key
    if args.key_init:
        try:
            if os.path.exists(f"{homeD}{path_seperator}sc0pe_Base"):
                pass
            else:
                os.system(f"mkdir {homeD}{path_seperator}sc0pe_Base")

            apikey = str(input(f"{infoC} Enter your VirusTotal API key: "))
            apifile = open(f"{homeD}{path_seperator}sc0pe_Base{path_seperator}sc0pe_VT_apikey.txt", "w")
            apifile.write(apikey)
            print(f"{foundS} Your VirusTotal API key saved.")
        except KeyboardInterrupt:
            print("\n[bold white on red]Program terminated by user.\n")

    

def cleanup_junks():
    junkFiles = ["temp.txt", ".target-file.txt", ".target-folder.txt"]
    for junk in junkFiles:
        if os.path.exists(junk):
            try: # assume simple file
                os.unlink(junk)
            except OSError: # try this for directories
                shutil.rmtree(junk)

def main():
    try:
        Malsecure()
    except KeyboardInterrupt:
        print("\n[bold white on red]Program terminated by user.\n")
    finally: # ensure cleanup irrespective of errors
        cleanup_junks()


# This is the entrypoint when directly running
# this module as a standalone program
# (as opposed to it being imported/ran like a lib)
if __name__ == "__main__":
    main()