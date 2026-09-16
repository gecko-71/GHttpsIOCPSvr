import os
import sys
import platform
import msvcrt

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

FG_CYAN = "\033[36m"
FG_BRIGHT_CYAN = "\033[96m"
FG_GREEN = "\033[32m"
FG_BRIGHT_GREEN = "\033[92m"
FG_YELLOW = "\033[33m"
FG_BRIGHT_YELLOW = "\033[93m"
FG_BLUE = "\033[34m"
FG_MAGENTA = "\033[35m"
FG_WHITE = "\033[37m"
FG_GRAY = "\033[90m"

BG_BLUE = "\033[44m"
BG_DARK = "\033[48;5;236m"
BG_HIGHLIGHT = "\033[48;5;24m"

def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def read_key():
    ch = msvcrt.getwch()
    if ch in ('\x00', '\xe0'):
        ext = msvcrt.getwch()
        if ext == 'H':
            return 'UP'
        elif ext == 'P':
            return 'DOWN'
        elif ext == 'K':
            return 'LEFT'
        elif ext == 'M':
            return 'RIGHT'
        return ext
    elif ch == '\r':
        return 'ENTER'
    elif ch == '\x1b':
        return 'ESC'
    return ch

def draw_header():
    w = 78
    title = "GTermBox - Python TUI VirtualEnv Demonstration"
    sys.stdout.write(f"{FG_BRIGHT_CYAN}{BOLD}╔{'═' * (w - 2)}╗{RESET}\n")
    sys.stdout.write(f"{FG_BRIGHT_CYAN}{BOLD}║{FG_WHITE}{title:^{w - 2}}{FG_BRIGHT_CYAN}║{RESET}\n")
    sys.stdout.write(f"{FG_BRIGHT_CYAN}{BOLD}╚{'═' * (w - 2)}╝{RESET}\n")

def show_system_info():
    clear_screen()
    draw_header()
    print(f"\n{FG_BRIGHT_YELLOW}{BOLD}[ System & Runtime Information ]{RESET}\n")
    info = [
        ("Platform", platform.platform()),
        ("Architecture", platform.machine()),
        ("Processor", platform.processor() or "x86_64"),
        ("Python Version", sys.version.split()[0]),
        ("Executable", sys.executable),
        ("In VirtualEnv", str(sys.prefix != sys.base_prefix)),
        ("VirtualEnv Prefix", sys.prefix),
        ("Current Working Dir", os.getcwd()),
        ("Process ID", str(os.getpid()))
    ]
    for key, val in info:
        print(f"  {FG_CYAN}{key:<22}{RESET} : {FG_WHITE}{val}{RESET}")
    print(f"\n{FG_GRAY}Press any key to return to menu...{RESET}")
    read_key()

def show_env_vars():
    clear_screen()
    draw_header()
    print(f"\n{FG_BRIGHT_YELLOW}{BOLD}[ Environment Variables ]{RESET}\n")
    tracked = ["USERPROFILE", "HOMEDRIVE", "HOMEPATH", "TERM", "COLORTERM", "TEMP", "TMP", "PYTHONIOENCODING", "PATH"]
    for var in tracked:
        val = os.environ.get(var, f"{FG_GRAY}<not set>{RESET}")
        if var == "PATH" and len(val) > 80:
            parts = val.split(';')
            print(f"  {FG_CYAN}{var:<18}{RESET} :")
            for p in parts[:4]:
                if p:
                    print(f"    {FG_GRAY}- {p}{RESET}")
            if len(parts) > 4:
                print(f"    {FG_GRAY}... ({len(parts)-4} more entries){RESET}")
        else:
            print(f"  {FG_CYAN}{var:<18}{RESET} : {FG_WHITE}{val}{RESET}")
    print(f"\n{FG_GRAY}Press any key to return to menu...{RESET}")
    read_key()

def show_color_demo():
    clear_screen()
    draw_header()
    print(f"\n{FG_BRIGHT_YELLOW}{BOLD}[ 256-Color & Unicode Box Drawing Demo ]{RESET}\n")
    print("  Standard Colors:")
    colors = [
        ("Black", "\033[30m"), ("Red", "\033[31m"), ("Green", "\033[32m"),
        ("Yellow", "\033[33m"), ("Blue", "\033[34m"), ("Magenta", "\033[35m"),
        ("Cyan", "\033[36m"), ("White", "\033[37m")
    ]
    line = "    "
    for name, c in colors:
        line += f"{c}██ {name}{RESET}  "
    print(line)

    print("\n  Bright Colors:")
    brights = [
        ("B-Red", "\033[91m"), ("B-Green", "\033[92m"), ("B-Yellow", "\033[93m"),
        ("B-Blue", "\033[94m"), ("B-Magenta", "\033[95m"), ("B-Cyan", "\033[96m"),
        ("B-White", "\033[97m")
    ]
    line = "    "
    for name, c in brights:
        line += f"{c}██ {name}{RESET}  "
    print(line)

    print("\n  Box Drawing Grid:")
    print(f"    {FG_BRIGHT_CYAN}┌───────┬───────┬───────┐{RESET}")
    print(f"    {FG_BRIGHT_CYAN}│ {FG_WHITE}Far   {FG_BRIGHT_CYAN}│ {FG_WHITE}Edit  {FG_BRIGHT_CYAN}│ {FG_WHITE}PS    {FG_BRIGHT_CYAN}│{RESET}")
    print(f"    {FG_BRIGHT_CYAN}├───────┼───────┼───────┤{RESET}")
    print(f"    {FG_BRIGHT_CYAN}│ {FG_GREEN}OK    {FG_BRIGHT_CYAN}│ {FG_GREEN}OK    {FG_BRIGHT_CYAN}│ {FG_GREEN}OK    {FG_BRIGHT_CYAN}│{RESET}")
    print(f"    {FG_BRIGHT_CYAN}└───────┴───────┴───────┘{RESET}")

    print(f"\n{FG_GRAY}Press any key to return to menu...{RESET}")
    read_key()

def show_interactive_echo():
    clear_screen()
    draw_header()
    print(f"\n{FG_BRIGHT_YELLOW}{BOLD}[ Interactive Terminal Input Echo ]{RESET}\n")
    print(f"  {FG_WHITE}Type something and press ENTER (or type 'exit' to return):{RESET}\n")
    while True:
        try:
            sys.stdout.write(f"  {FG_BRIGHT_GREEN}input > {RESET}")
            sys.stdout.flush()
            val = input()
            if not val or val.strip().lower() in ('exit', 'quit', 'q'):
                break
            print(f"  {FG_CYAN}echo  > {FG_WHITE}{val.upper()}{RESET}  {FG_GRAY}(len={len(val)}){RESET}\n")
        except (EOFError, KeyboardInterrupt):
            break

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('--test', '--version', '-v'):
        print(f"GTermBox PyTui Demo 1.0 (Python {sys.version.split()[0]} venv)")
        sys.exit(0)

    menu_items = [
        ("System Information", show_system_info),
        ("Environment Variables", show_env_vars),
        ("Color Palette & Box Drawing", show_color_demo),
        ("Interactive Echo Test", show_interactive_echo),
        ("Exit Application", None)
    ]

    selected = 0

    while True:
        clear_screen()
        draw_header()
        
        sandbox_name = os.path.basename(os.getcwd())
        print(f"  {FG_GRAY}Active Sandbox : {FG_BRIGHT_GREEN}{sandbox_name}{RESET}")
        print(f"  {FG_GRAY}VirtualEnv     : {FG_CYAN}{sys.prefix}{RESET}\n")
        
        print(f"  {FG_WHITE}{BOLD}Select an action (Use UP/DOWN arrows, ENTER to select, Q to quit):{RESET}\n")
        
        for idx, (label, _) in enumerate(menu_items):
            if idx == selected:
                print(f"    {FG_BRIGHT_CYAN}{BOLD}▶ {BG_HIGHLIGHT} {label:<32} {RESET}")
            else:
                print(f"      {FG_WHITE}{label:<32}{RESET}")
        
        print(f"\n  {FG_GRAY}───────────────────────────────────────────────────{RESET}")
        print(f"  {FG_GRAY}[↑/↓] Navigate   [Enter] Select   [Q/Esc] Quit{RESET}")
        
        key = read_key()
        if key == 'UP':
            selected = (selected - 1) % len(menu_items)
        elif key == 'DOWN':
            selected = (selected + 1) % len(menu_items)
        elif key == 'ENTER':
            action = menu_items[selected][1]
            if action is None:
                break
            action()
        elif key in ('q', 'Q', 'ESC'):
            break

    clear_screen()
    print(f"\n{FG_GREEN}Exited Python TUI Demo successfully.{RESET}\n")

if __name__ == '__main__':
    main()
