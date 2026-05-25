#!/usr/bin/env python3
"""
TraceMind - Maximum Subdomain Discovery Tool

Authorized DNS reconnaissance helper for Linux/Kali.
It combines existing recon tools, passive APIs, clean extraction, and DNS
resolution into one beginner-friendly command-line workflow.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


CORE_TOOLS = [
    "subfinder",
    "sublist3r",
    "amass",
    "dnsrecon",
    "theHarvester",
    "dig",
    "host",
]

OPTIONAL_ENUM_TOOLS = [
    "bbot",
    "findomain",
    "knockpy",
    "darkscout",
]

THEHARVESTER_SOURCES = [
    "crtsh",
    "rapiddns",
    "urlscan",
    "waybackarchive",
    "threatminer",
    "hackertarget",
    "duckduckgo",
    "yahoo",
    "brave",
    "commoncrawl",
    "otx",
    "projectdiscovery",
    "subdomaincenter",
    "subdomainfinderc99",
    "dnsdumpster",
]

PUBLIC_API_SOURCES = [
    "crtsh",
    "alienvault",
    "threatminer",
    "hackertarget",
    "anubis",
]

KEYED_API_ENV_VARS = {
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "dnsdumpster": "DNSDUMPSTER_API_KEY",
    "shodan": "SHODAN_API_KEY",
}

USER_AGENT = "TraceMind/2.1 Authorized Subdomain Discovery"

TRACE_BANNER = r"""
 _____                   __  __ _           _
|_   _| __ __ _  ___ ___|  \/  (_)_ __   __| |
  | || '__/ _` |/ __/ _ \ |\/| | | '_ \ / _` |
  | || | | (_| | (_|  __/ |  | | | | | | (_| |
  |_||_|  \__,_|\___\___|_|  |_|_|_| |_|\__,_|
"""


def print_banner():
    """Print the tool banner and ethics warning."""
    print(TRACE_BANNER)
    print("TraceMind - Maximum Subdomain Discovery Tool")
    print("A simple, modern subdomain discovery and DNS reconnaissance tool.")
    print()
    print("=" * 66)
    print("Use this tool only on domains/IPs you own or have permission to test.")
    print("=" * 66)
    print()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="TraceMind - authorized subdomain discovery and DNS reconnaissance tool."
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target root domain or IP address, for example example.com or 192.168.1.10",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="final_subdomains_with_ip.txt",
        help="Final output file name. Default: final_subdomains_with_ip.txt",
    )
    parser.add_argument(
        "--wordlist",
        help="Optional DNS brute force wordlist path.",
    )
    parser.add_argument(
        "--keep-raw",
        action="store_true",
        help="Keep raw output files. Raw files are kept by default inside the output folder.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for each external command or API request. Default: 300",
    )
    parser.add_argument(
        "--resolver-workers",
        type=int,
        default=20,
        help="Parallel DNS resolver workers. Default: 20",
    )
    parser.add_argument(
        "--skip-apis",
        action="store_true",
        help="Skip built-in passive web/API sources.",
    )
    parser.add_argument(
        "--bbot-full",
        action="store_true",
        help="Run BBOT's full subdomain-enum preset instead of the safer passive-only filter.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show detailed command execution errors.",
    )
    return parser.parse_args()


def sanitize_target_for_folder(target):
    """Create a safe folder-name fragment from a domain or IP address."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


def create_output_folder(target):
    """Create the timestamped TraceMind output folder."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"tracemind_{sanitize_target_for_folder(target)}_{timestamp}"
    output_folder = Path(folder_name)
    output_folder.mkdir(parents=True, exist_ok=True)
    return output_folder


def check_tools():
    """Check external command availability using shutil.which()."""
    found = {}

    print("[*] Checking required external tools...")
    for tool in CORE_TOOLS:
        path = find_tool_path(tool)
        found[tool] = path
        if path:
            print(f"[+] Found {tool}: {path}")
        else:
            print(f"[!] Warning: {tool} is not installed or not in PATH. Continuing without it.")

    print()
    print("[*] Checking optional public subdomain tools...")
    for tool in OPTIONAL_ENUM_TOOLS:
        path = find_tool_path(tool)
        found[tool] = path
        if path:
            print(f"[+] Found optional tool {tool}: {path}")
        else:
            print(f"[-] Optional public tool skipped because it is not installed: {tool}")

    print()
    return found


def find_tool_path(tool):
    """Find a command in PATH plus common Kali user/global bin folders."""
    path = shutil.which(tool)
    if path:
        return path

    candidates = [
        Path.home() / ".local" / "bin" / tool,
        Path("/usr/local/bin") / tool,
        Path("/usr/bin") / tool,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def is_ip_address(target):
    """Return True if target is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def normalize_domain(domain):
    """Normalize a user-provided domain for matching."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def validate_domain(domain):
    """Return True when a normalized target looks like a domain name."""
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if re.fullmatch(r"[a-z0-9-]+", label) is None:
            return False
    return True


def run_command(command, output_file, timeout, debug=False, tool_writes_output=False, cwd=None):
    """
    Run an external command safely and save stdout/stderr to a raw output file.

    Returns True when the command exits with status 0, otherwise False.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=cwd,
        )

        mode = "a" if tool_writes_output and output_file.exists() else "w"
        with output_file.open(mode, encoding="utf-8", errors="ignore") as handle:
            write_command_log(handle, command, result.stdout, result.stderr)

        if result.returncode != 0:
            print(f"[!] Command failed with exit code {result.returncode}: {' '.join(command)}")
            if debug:
                print(f"    Raw output saved to: {output_file}")
            return False

        return True

    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout} seconds: {' '.join(command)}")
        append_error_note(output_file, f"# Command timed out after {timeout} seconds: {' '.join(command)}\n")
        return False
    except FileNotFoundError:
        print(f"[!] Command not found: {command[0]}")
        append_error_note(output_file, f"# Command not found: {command[0]}\n")
        return False
    except OSError as exc:
        print(f"[!] Could not run command: {' '.join(command)}")
        if debug:
            print(f"    Error: {exc}")
        append_error_note(output_file, f"# Could not run command: {' '.join(command)}\n# Error: {exc}\n")
        return False


def append_error_note(path, message):
    """Append an error note to a raw output file without deleting partial results."""
    with path.open("a", encoding="utf-8", errors="ignore") as handle:
        handle.write(message)


def write_command_log(handle, command, stdout, stderr):
    """Append command context and captured console output to a raw file."""
    handle.write(f"\n# Command: {' '.join(command)}\n")
    if stdout:
        handle.write("\n# STDOUT\n")
        handle.write(stdout)
        if not stdout.endswith("\n"):
            handle.write("\n")
    if stderr:
        handle.write("\n# STDERR\n")
        handle.write(stderr)
        if not stderr.endswith("\n"):
            handle.write("\n")


def write_missing_tool_file(path, tool_name):
    """Create a small raw file explaining that a tool was skipped."""
    path.write_text(f"# Skipped because {tool_name} was not installed or not in PATH.\n", encoding="utf-8")
    return path


def write_skipped_file(path, reason):
    """Create a small raw file explaining why a source was skipped."""
    path.write_text(f"# Skipped: {reason}\n", encoding="utf-8")
    return path


def write_raw_api_file(path, source_name, request_note, body, extra_lines=None):
    """Write an API response and any extracted helper lines to a raw file."""
    with path.open("w", encoding="utf-8", errors="ignore") as handle:
        handle.write(f"# Source: {source_name}\n")
        handle.write(f"# Request: {request_note}\n\n")
        if body:
            handle.write(body)
            if not body.endswith("\n"):
                handle.write("\n")
        if extra_lines:
            handle.write("\n# Extracted hostnames\n")
            for line in extra_lines:
                handle.write(f"{line}\n")
    return path


def run_domain_tools(domain, output_folder, tools, wordlist, timeout, debug, skip_apis, bbot_full):
    """Run all configured domain reconnaissance tools."""
    raw_files = []
    raw_files.extend(run_core_domain_tools(domain, output_folder, tools, wordlist, timeout, debug))
    raw_files.extend(run_optional_cli_tools(domain, output_folder, tools, timeout, debug, bbot_full))

    if skip_apis:
        print("[*] Built-in passive API sources skipped by user request.")
        for source in PUBLIC_API_SOURCES:
            raw_files.append(write_skipped_file(output_folder / f"raw_public_{source}.txt", "--skip-apis was used"))
        for source in KEYED_API_ENV_VARS:
            raw_files.append(write_skipped_file(output_folder / f"raw_{source}.txt", "--skip-apis was used"))
    else:
        raw_files.extend(run_public_passive_apis(domain, output_folder, timeout, debug))
        raw_files.extend(run_keyed_apis(domain, output_folder, timeout, debug))

    return raw_files


def run_core_domain_tools(domain, output_folder, tools, wordlist, timeout, debug):
    """Run the original TraceMind toolchain."""
    raw_files = []

    if tools.get("subfinder"):
        print("[*] Running subfinder...")
        path = output_folder / "raw_subfinder.txt"
        run_command(
            [tools["subfinder"], "-d", domain, "-all", "-silent", "-o", str(path)],
            path,
            timeout,
            debug,
            tool_writes_output=True,
        )
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_subfinder.txt", "subfinder"))

    if tools.get("sublist3r"):
        print("[*] Running Sublist3r...")
        path = output_folder / "raw_sublist3r.txt"
        run_command(
            [tools["sublist3r"], "-d", domain, "-o", str(path)],
            path,
            timeout,
            debug,
            tool_writes_output=True,
        )
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_sublist3r.txt", "sublist3r"))

    if tools.get("amass"):
        print("[*] Running Amass passive...")
        path = output_folder / "raw_amass_passive.txt"
        run_command(
            [tools["amass"], "enum", "-passive", "-d", domain, "-o", str(path)],
            path,
            timeout,
            debug,
            tool_writes_output=True,
        )
        raw_files.append(path)

        print("[*] Running Amass brute force...")
        path = output_folder / "raw_amass_brute.txt"
        command = [tools["amass"], "enum", "-brute"]
        if wordlist:
            command.extend(["-w", str(wordlist)])
        command.extend(["-d", domain, "-o", str(path)])
        run_command(command, path, timeout, debug, tool_writes_output=True)
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_amass_passive.txt", "amass"))
        raw_files.append(write_missing_tool_file(output_folder / "raw_amass_brute.txt", "amass"))

    if tools.get("dnsrecon"):
        print("[*] Running DNSRecon...")
        path = output_folder / "raw_dnsrecon.txt"
        run_command([tools["dnsrecon"], "-d", domain, "-a", "-k"], path, timeout, debug)
        raw_files.append(path)

        brute_path = output_folder / "raw_dnsrecon_brute.txt"
        if wordlist:
            print("[*] Running DNSRecon brute force...")
            run_command([tools["dnsrecon"], "-d", domain, "-D", str(wordlist), "-t", "brt"], brute_path, timeout, debug)
        else:
            brute_path.write_text(
                "# DNSRecon brute force skipped because no wordlist was provided.\n",
                encoding="utf-8",
            )
        raw_files.append(brute_path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_dnsrecon.txt", "dnsrecon"))
        raw_files.append(write_missing_tool_file(output_folder / "raw_dnsrecon_brute.txt", "dnsrecon"))

    if tools.get("theHarvester"):
        for source in THEHARVESTER_SOURCES:
            print(f"[*] Running theHarvester source: {source}")
            path = output_folder / f"raw_theharvester_{source}.txt"
            run_command(
                [tools["theHarvester"], "-d", domain, "-b", source, "-l", "1000", "-r"],
                path,
                timeout,
                debug,
            )
            raw_files.append(path)

        print("[*] Running theHarvester all brute attempt...")
        all_brute_path = output_folder / "raw_theharvester_all_brute.txt"
        success = run_command(
            [tools["theHarvester"], "-d", domain, "-b", "all", "-c"],
            all_brute_path,
            timeout,
            debug,
        )
        if not success:
            print("[!] theHarvester -b all failed or is unsupported. Continuing with valid source loop.")
        raw_files.append(all_brute_path)
    else:
        for source in THEHARVESTER_SOURCES:
            raw_files.append(
                write_missing_tool_file(output_folder / f"raw_theharvester_{source}.txt", "theHarvester")
            )
        raw_files.append(write_missing_tool_file(output_folder / "raw_theharvester_all_brute.txt", "theHarvester"))

    return raw_files


def run_optional_cli_tools(domain, output_folder, tools, timeout, debug, bbot_full):
    """Run optional subdomain enumeration CLIs requested by the user."""
    raw_files = []

    if tools.get("bbot"):
        print("[*] Running BBOT subdomain enumeration...")
        path = output_folder / "raw_bbot.txt"
        command = [tools["bbot"], "-t", domain, "-f", "subdomain-enum", "-n", "tracemind_bbot", "-o", str(output_folder)]
        if not bbot_full:
            command.extend(["-rf", "passive"])
        run_command(command, path, timeout, debug)
        raw_files.append(path)
        raw_files.extend(collect_bbot_txt_outputs(output_folder))
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_bbot.txt", "bbot"))

    if tools.get("findomain"):
        print("[*] Running Findomain...")
        path = output_folder / "raw_findomain.txt"
        run_command(
            [tools["findomain"], "-t", domain, "-u", str(path)],
            path,
            timeout,
            debug,
            tool_writes_output=True,
        )
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_findomain.txt", "findomain"))

    if tools.get("darkscout"):
        print("[*] Running DarkScout...")
        path = output_folder / "raw_darkscout.txt"
        run_command(
            [tools["darkscout"], "-t", domain, "-o", str(path)],
            path,
            timeout,
            debug,
            tool_writes_output=True,
        )
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_darkscout.txt", "darkscout"))

    if tools.get("knockpy"):
        print("[*] Running Knockpy...")
        path = output_folder / "raw_knockpy.txt"
        run_command(
            [tools["knockpy"], "--no-http", "--silent", "csv", domain],
            path,
            timeout,
            debug,
        )
        raw_files.append(path)
    else:
        raw_files.append(write_missing_tool_file(output_folder / "raw_knockpy.txt", "knockpy"))

    return raw_files


def collect_bbot_txt_outputs(output_folder):
    """Collect BBOT-created text outputs when present."""
    collected = []
    scan_folder = output_folder / "tracemind_bbot"
    if not scan_folder.exists():
        return collected

    for path in sorted(scan_folder.rglob("*.txt")):
        if path.is_file():
            collected.append(path)
    return collected


def run_public_passive_apis(domain, output_folder, timeout, debug):
    """Run built-in public passive sources that do not require API keys."""
    raw_files = []
    raw_files.append(run_crtsh_api(domain, output_folder, timeout, debug))
    raw_files.append(run_alienvault_api(domain, output_folder, timeout, debug))
    raw_files.append(run_threatminer_api(domain, output_folder, timeout, debug))
    raw_files.append(run_hackertarget_api(domain, output_folder, timeout, debug))
    raw_files.append(run_anubis_api(domain, output_folder, timeout, debug))
    return raw_files


def run_keyed_apis(domain, output_folder, timeout, debug):
    """Run optional public API integrations when their API keys exist."""
    raw_files = []
    raw_files.append(run_securitytrails_api(domain, output_folder, timeout, debug))
    raw_files.append(run_dnsdumpster_api(domain, output_folder, timeout, debug))
    raw_files.extend(run_shodan_api(domain, output_folder, timeout, debug))
    return raw_files


def api_get(url, timeout, headers=None, debug=False):
    """Perform a GET request with urllib and return response text."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"}
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return True, response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        if debug:
            print(f"[!] API HTTP error {exc.code} for {safe_url_for_print(url)}: {body[:300]}")
        return False, exc.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if debug:
            print(f"[!] API request failed for {safe_url_for_print(url)}: {exc}")
        return False, 0, str(exc)


def safe_url_for_print(url):
    """Hide obvious API keys from URLs before printing or saving them."""
    return re.sub(r"(?i)(key|apikey|api_key|token)=([^&]+)", r"\1=<redacted>", url)


def parse_json_or_none(text):
    """Parse JSON text and return None if it is not JSON."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def pretty_json_or_text(text):
    """Return pretty JSON when possible, otherwise return the original text."""
    data = parse_json_or_none(text)
    if data is None:
        return text
    return json.dumps(data, indent=2, sort_keys=True)


def run_crtsh_api(domain, output_folder, timeout, debug):
    """Query crt.sh directly as a public passive source."""
    print("[*] Querying public source: crt.sh")
    path = output_folder / "raw_public_crtsh.txt"
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"
    if not success:
        return write_raw_api_file(path, "crt.sh", note, body)

    data = parse_json_or_none(body)
    hostnames = []
    if isinstance(data, list):
        for row in data:
            value = row.get("name_value") if isinstance(row, dict) else None
            if not value:
                continue
            for item in str(value).splitlines():
                hostnames.append(item.strip())
    return write_raw_api_file(path, "crt.sh", note, pretty_json_or_text(body), hostnames)


def run_alienvault_api(domain, output_folder, timeout, debug):
    """Query AlienVault OTX passive DNS."""
    print("[*] Querying public source: AlienVault OTX")
    path = output_folder / "raw_public_alienvault.txt"
    encoded = urllib.parse.quote(domain)
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{encoded}/passive_dns"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        for row in data.get("passive_dns", []):
            if isinstance(row, dict):
                hostname = row.get("hostname")
                if hostname:
                    hostnames.append(str(hostname))
    return write_raw_api_file(path, "AlienVault OTX", note, pretty_json_or_text(body), hostnames)


def run_threatminer_api(domain, output_folder, timeout, debug):
    """Query ThreatMiner domain subdomains endpoint."""
    print("[*] Querying public source: ThreatMiner")
    path = output_folder / "raw_public_threatminer.txt"
    encoded = urllib.parse.quote(domain)
    url = f"https://api.threatminer.org/v2/domain.php?q={encoded}&rt=5"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        for item in data.get("results", []):
            if isinstance(item, str):
                hostnames.append(item)
            elif isinstance(item, dict):
                for value in item.values():
                    if isinstance(value, str):
                        hostnames.append(value)
    return write_raw_api_file(path, "ThreatMiner", note, pretty_json_or_text(body), hostnames)


def run_hackertarget_api(domain, output_folder, timeout, debug):
    """Query HackerTarget hostsearch."""
    print("[*] Querying public source: HackerTarget")
    path = output_folder / "raw_public_hackertarget.txt"
    encoded = urllib.parse.quote(domain)
    url = f"https://api.hackertarget.com/hostsearch/?q={encoded}"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"
    return write_raw_api_file(path, "HackerTarget", note, body)


def run_anubis_api(domain, output_folder, timeout, debug):
    """Query AnubisDB subdomain source."""
    print("[*] Querying public source: AnubisDB")
    path = output_folder / "raw_public_anubis.txt"
    encoded = urllib.parse.quote(domain)
    url = f"https://jldc.me/anubis/subdomains/{encoded}"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, list):
        hostnames = [str(item) for item in data]
    return write_raw_api_file(path, "AnubisDB", note, pretty_json_or_text(body), hostnames)


def run_securitytrails_api(domain, output_folder, timeout, debug):
    """Query SecurityTrails List Subdomains when SECURITYTRAILS_API_KEY is set."""
    path = output_folder / "raw_securitytrails.txt"
    api_key = os.environ.get(KEYED_API_ENV_VARS["securitytrails"])
    if not api_key:
        return write_skipped_file(path, "SECURITYTRAILS_API_KEY is not set")

    print("[*] Querying SecurityTrails API...")
    encoded = urllib.parse.quote(domain)
    url = f"https://api.securitytrails.com/v1/domain/{encoded}/subdomains"
    success, status, body = api_get(url, timeout, headers={"APIKEY": api_key}, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        for item in data.get("subdomains", []):
            hostname = complete_hostname(item, domain)
            if hostname:
                hostnames.append(hostname)
    return write_raw_api_file(path, "SecurityTrails", note, pretty_json_or_text(body), hostnames)


def run_dnsdumpster_api(domain, output_folder, timeout, debug):
    """Query DNSDumpster official API when DNSDUMPSTER_API_KEY is set."""
    path = output_folder / "raw_dnsdumpster.txt"
    api_key = os.environ.get(KEYED_API_ENV_VARS["dnsdumpster"])
    if not api_key:
        return write_skipped_file(path, "DNSDUMPSTER_API_KEY is not set")

    print("[*] Querying DNSDumpster API...")
    encoded = urllib.parse.quote(domain)
    url = f"https://api.dnsdumpster.com/domain/{encoded}"
    success, status, body = api_get(url, timeout, headers={"X-API-Key": api_key}, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        hostnames.extend(extract_hosts_from_json(data, ("host", "hostname", "domain", "name")))
    return write_raw_api_file(path, "DNSDumpster", note, pretty_json_or_text(body), hostnames)


def run_shodan_api(domain, output_folder, timeout, debug):
    """Query passive Shodan API sources when SHODAN_API_KEY is set."""
    domain_path = output_folder / "raw_shodan_domain.txt"
    search_path = output_folder / "raw_shodan_search.txt"
    api_key = os.environ.get(KEYED_API_ENV_VARS["shodan"])
    if not api_key:
        return [
            write_skipped_file(domain_path, "SHODAN_API_KEY is not set"),
            write_skipped_file(search_path, "SHODAN_API_KEY is not set"),
        ]

    return [
        run_shodan_domain_lookup(domain, domain_path, api_key, timeout, debug),
        run_shodan_host_search(domain, search_path, api_key, timeout, debug),
    ]


def run_shodan_domain_lookup(domain, path, api_key, timeout, debug):
    """Use Shodan DNS domain lookup to collect known subdomain labels."""
    print("[*] Querying Shodan DNS domain lookup...")
    encoded_domain = urllib.parse.quote(domain)
    encoded_key = urllib.parse.quote(api_key)
    url = f"https://api.shodan.io/dns/domain/{encoded_domain}?key={encoded_key}"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        for item in data.get("subdomains", []):
            hostname = complete_hostname(item, domain)
            if hostname:
                hostnames.append(hostname)
        hostnames.extend(extract_shodan_hostnames(data, domain))

    return write_raw_api_file(path, "Shodan DNS Domain Lookup", note, pretty_json_or_text(body), hostnames)


def run_shodan_host_search(domain, path, api_key, timeout, debug):
    """Use Shodan host search for hostnames related to the target domain."""
    print("[*] Querying Shodan host search...")
    encoded_key = urllib.parse.quote(api_key)
    query = urllib.parse.quote(f"hostname:{domain}")
    fields = urllib.parse.quote("hostnames,domains,ip_str,port,ssl")
    url = f"https://api.shodan.io/shodan/host/search?key={encoded_key}&query={query}&fields={fields}"
    success, status, body = api_get(url, timeout, debug=debug)
    note = f"GET {safe_url_for_print(url)} status={status}"

    hostnames = []
    data = parse_json_or_none(body)
    if isinstance(data, dict):
        hostnames.extend(extract_shodan_hostnames(data, domain))

    return write_raw_api_file(path, "Shodan Host Search", note, pretty_json_or_text(body), hostnames)


def extract_shodan_hostnames(value, domain):
    """Recursively collect target-domain hostnames from Shodan JSON data."""
    hostnames = set()

    if isinstance(value, dict):
        for key, child in value.items():
            lower_key = key.lower()
            if lower_key in {"hostname", "hostnames", "name", "cn", "alt_names"}:
                hostnames.update(extract_hostname_strings(child, domain))
            else:
                hostnames.update(extract_shodan_hostnames(child, domain))
    elif isinstance(value, list):
        for child in value:
            hostnames.update(extract_shodan_hostnames(child, domain))

    return sorted(hostnames)


def extract_hostname_strings(value, domain):
    """Collect clean hostname strings from nested Shodan values."""
    hostnames = set()

    if isinstance(value, str):
        hostname = clean_hostname(value)
        if is_valid_subdomain(hostname, domain):
            hostnames.add(hostname)
    elif isinstance(value, list):
        for item in value:
            hostnames.update(extract_hostname_strings(item, domain))
    elif isinstance(value, dict):
        for item in value.values():
            hostnames.update(extract_hostname_strings(item, domain))

    return hostnames


def complete_hostname(value, domain):
    """Convert a relative subdomain label into a full hostname."""
    if value is None:
        return ""
    hostname = str(value).strip().strip(".").lower()
    if not hostname or hostname == "*":
        return ""
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if hostname == domain:
        return hostname
    if hostname.endswith(f".{domain}"):
        return hostname
    return f"{hostname}.{domain}"


def extract_hosts_from_json(value, host_keys):
    """Recursively collect likely hostname fields from JSON data."""
    hostnames = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in host_keys and isinstance(child, str):
                hostnames.append(child)
            else:
                hostnames.extend(extract_hosts_from_json(child, host_keys))
    elif isinstance(value, list):
        for child in value:
            hostnames.extend(extract_hosts_from_json(child, host_keys))
    return hostnames


def combine_raw_files(raw_files, combined_file):
    """Combine all raw text files into all_raw.txt and return total line count."""
    print("[*] Combining raw results...")
    total_lines = 0
    seen_paths = set()

    with combined_file.open("w", encoding="utf-8", errors="ignore") as output:
        for raw_file in raw_files:
            if raw_file in seen_paths:
                continue
            seen_paths.add(raw_file)
            output.write(f"\n\n# ===== {raw_file.name} =====\n")
            if not raw_file.exists():
                continue
            with raw_file.open("r", encoding="utf-8", errors="ignore") as source:
                for line in source:
                    output.write(line)
                    total_lines += 1
    return total_lines


def extract_subdomains(combined_file, domain):
    """Extract clean unique subdomains belonging to the target domain using regex."""
    print("[*] Extracting clean subdomains...")
    domain = normalize_domain(domain)
    escaped_domain = re.escape(domain)
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.-])(?:\*\.)?("
        rf"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+{escaped_domain}"
        rf")(?![A-Za-z0-9_.-])",
        re.IGNORECASE,
    )

    text = combined_file.read_text(encoding="utf-8", errors="ignore")
    subdomains = set()

    for match in pattern.finditer(text):
        subdomain = clean_hostname(match.group(1))
        if is_valid_subdomain(subdomain, domain):
            subdomains.add(subdomain)

    return sorted(subdomains)


def clean_hostname(hostname):
    """Normalize a hostname candidate."""
    hostname = hostname.lower().strip().strip(".")
    hostname = hostname.strip("[](){}<>,;:'\"")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    return hostname


def is_valid_subdomain(hostname, domain):
    """Validate that a hostname is a clean subdomain for the target domain."""
    if not hostname or not hostname.endswith(f".{domain}"):
        return False
    if hostname == domain:
        return False
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    if any(not label for label in labels):
        return False
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return re.fullmatch(r"[a-z0-9.-]+", hostname) is not None


def save_lines(path, lines):
    """Write lines to a text file."""
    with path.open("w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"{line}\n")


def resolve_with_dnspython(hostname):
    """Resolve a hostname with dnspython if it is installed."""
    try:
        import dns.resolver
    except ImportError:
        return None

    ips = set()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6
    resolver.timeout = 3

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, record_type)
            for answer in answers:
                value = answer.to_text().strip()
                if is_ip_address(value):
                    ips.add(value)
        except Exception:
            continue

    return sorted(ips)


def has_dnspython():
    """Return True when dnspython is installed."""
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def resolve_with_dig(hostname, timeout, debug=False):
    """Resolve a hostname with dig +short as a fallback."""
    if not shutil.which("dig"):
        return []

    ips = set()
    for record_type in ("A", "AAAA"):
        try:
            result = subprocess.run(
                ["dig", "+short", hostname, record_type],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode != 0:
                if debug:
                    print(f"[!] dig failed for {hostname} {record_type}: {result.stderr.strip()}")
                continue

            for line in result.stdout.splitlines():
                value = line.strip()
                if is_ip_address(value):
                    ips.add(value)
        except subprocess.TimeoutExpired:
            if debug:
                print(f"[!] dig timed out for {hostname} {record_type}")
        except OSError as exc:
            if debug:
                print(f"[!] dig error for {hostname} {record_type}: {exc}")

    return sorted(ips)


def resolve_with_host(hostname, timeout, debug=False):
    """Resolve a hostname with host as a last command-line fallback."""
    if not shutil.which("host"):
        return []

    try:
        result = subprocess.run(
            ["host", hostname],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            if debug:
                print(f"[!] host failed for {hostname}: {result.stderr.strip()}")
            return []

        ips = set()
        for line in result.stdout.splitlines():
            match = re.search(r"\b(?:has address|has IPv6 address)\s+([0-9A-Fa-f:.]+)\b", line)
            if match and is_ip_address(match.group(1)):
                ips.add(match.group(1))
        return sorted(ips)
    except subprocess.TimeoutExpired:
        if debug:
            print(f"[!] host timed out for {hostname}")
    except OSError as exc:
        if debug:
            print(f"[!] host error for {hostname}: {exc}")
    return []


def resolve_one_subdomain(subdomain, timeout, debug, dnspython_available):
    """Resolve one subdomain and return a tuple of hostname and IP list."""
    ips = resolve_with_dnspython(subdomain) if dnspython_available else None
    if ips is None:
        ips = resolve_with_dig(subdomain, timeout, debug)
        if not ips:
            ips = resolve_with_host(subdomain, timeout, debug)
    return subdomain, ips


def resolve_subdomains(subdomains, timeout, workers, debug=False):
    """Resolve every clean subdomain and return final output lines."""
    print("[*] Resolving subdomains to IP addresses...")
    final_lines = []
    resolved_ip_entries = 0
    dnspython_available = has_dnspython()
    workers = max(1, min(workers, 100))

    if dnspython_available:
        print(f"[+] Using dnspython with {workers} resolver worker(s).")
    else:
        print(f"[!] dnspython is not installed. Falling back to dig/host with {workers} worker(s).")

    results = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(resolve_one_subdomain, subdomain, timeout, debug, dnspython_available): subdomain
            for subdomain in subdomains
        }
        for index, future in enumerate(as_completed(future_map), start=1):
            subdomain = future_map[future]
            try:
                _hostname, ips = future.result()
                results[subdomain] = ips
            except Exception as exc:
                if debug:
                    print(f"[!] Resolver error for {subdomain}: {exc}")
                results[subdomain] = []
            if index % 100 == 0:
                print(f"[*] Resolved {index}/{len(subdomains)} names...")

    for subdomain in subdomains:
        ips = results.get(subdomain, [])
        if ips:
            for ip in ips:
                final_lines.append(f"{subdomain} : {ip}")
                resolved_ip_entries += 1
        else:
            final_lines.append(f"{subdomain} : No IP found")

    return final_lines, resolved_ip_entries


def reverse_dns_with_socket(ip):
    """Try reverse DNS lookup with Python socket."""
    try:
        hostname, aliases, _addresses = socket.gethostbyaddr(ip)
        names = {hostname.rstrip(".")}
        names.update(alias.rstrip(".") for alias in aliases if alias)
        return sorted(name for name in names if name)
    except (socket.herror, socket.gaierror, OSError):
        return []


def reverse_dns_with_dig(ip, timeout, debug=False):
    """Try reverse DNS lookup with dig -x."""
    if not shutil.which("dig"):
        return []

    try:
        result = subprocess.run(
            ["dig", "-x", ip, "+short"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            if debug:
                print(f"[!] dig reverse lookup failed: {result.stderr.strip()}")
            return []

        return sorted(
            {
                line.strip().rstrip(".")
                for line in result.stdout.splitlines()
                if line.strip()
            }
        )
    except subprocess.TimeoutExpired:
        if debug:
            print(f"[!] dig reverse lookup timed out for {ip}")
    except OSError as exc:
        if debug:
            print(f"[!] dig reverse lookup error for {ip}: {exc}")
    return []


def reverse_dns_with_host(ip, timeout, debug=False):
    """Try reverse DNS lookup with host."""
    if not shutil.which("host"):
        return []

    try:
        result = subprocess.run(
            ["host", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            if debug:
                print(f"[!] host reverse lookup failed: {result.stderr.strip()}")
            return []

        names = set()
        for line in result.stdout.splitlines():
            match = re.search(r"domain name pointer\s+([A-Za-z0-9_.-]+)\.?", line)
            if match:
                names.add(match.group(1).rstrip("."))
        return sorted(names)
    except subprocess.TimeoutExpired:
        if debug:
            print(f"[!] host reverse lookup timed out for {ip}")
    except OSError as exc:
        if debug:
            print(f"[!] host reverse lookup error for {ip}: {exc}")
    return []


def output_path_in_folder(output_folder, output_name):
    """Return a final output path inside the TraceMind output folder."""
    output_file_name = Path(output_name).name
    if output_file_name != output_name:
        print(f"[!] Output path components ignored. Saving as: {output_file_name}")
    return output_folder / output_file_name


def run_ip_mode(ip, output_folder, output_name, tools, timeout, debug):
    """Handle IP input with reverse DNS/PTR lookups."""
    print("[*] IP address detected.")
    print("IP mode is limited. For maximum subdomain discovery, provide the root domain.")
    print("[*] Running reverse DNS/PTR lookup...")

    hostnames = set(reverse_dns_with_socket(ip))
    if tools.get("dig"):
        hostnames.update(reverse_dns_with_dig(ip, timeout, debug))
    if tools.get("host"):
        hostnames.update(reverse_dns_with_host(ip, timeout, debug))

    if hostnames:
        lines = [f"{hostname} : {ip}" for hostname in sorted(hostnames)]
    else:
        lines = [f"No PTR hostname found : {ip}"]

    output_path = output_path_in_folder(output_folder, output_name)
    save_lines(output_path, lines)
    print(f"[+] Saved final result: {output_path}")

    print()
    print("Summary")
    print(f"Target: {ip}")
    print("Mode: IP")
    print("Total raw lines collected: 0")
    print(f"Total unique subdomains: {len(hostnames)}")
    print(f"Total resolved IP entries: {len(lines) if hostnames else 0}")
    print(f"Final output file path: {output_path}")


def run_domain_mode(
    domain,
    output_folder,
    output_name,
    tools,
    wordlist,
    timeout,
    resolver_workers,
    debug,
    skip_apis,
    bbot_full,
):
    """Handle root domain input with maximum subdomain enumeration."""
    raw_files = run_domain_tools(
        domain,
        output_folder,
        tools,
        wordlist,
        timeout,
        debug,
        skip_apis,
        bbot_full,
    )

    combined_file = output_folder / "all_raw.txt"
    total_raw_lines = combine_raw_files(raw_files, combined_file)

    subdomains = extract_subdomains(combined_file, domain)
    clean_file = output_folder / "clean_subdomains.txt"
    save_lines(clean_file, subdomains)

    final_lines, resolved_ip_entries = resolve_subdomains(subdomains, timeout, resolver_workers, debug)
    output_path = output_path_in_folder(output_folder, output_name)
    save_lines(output_path, final_lines)

    print(f"[+] Saved final result: {output_path}")
    print()
    print("Summary")
    print(f"Target: {domain}")
    print("Mode: Domain")
    print(f"Total raw lines collected: {total_raw_lines}")
    print(f"Total unique subdomains: {len(subdomains)}")
    print(f"Total resolved IP entries: {resolved_ip_entries}")
    print(f"Final output file path: {output_path}")


def validate_wordlist(wordlist):
    """Return a Path for an existing wordlist, or None when not usable."""
    if not wordlist:
        return None

    path = Path(wordlist).expanduser()
    if path.is_file():
        return path

    print(f"[!] Wordlist not found: {path}")
    print("[!] DNS brute force steps that require this wordlist will be skipped or run without it.")
    return None


def main():
    """Program entry point."""
    print_banner()
    args = parse_args()

    if args.timeout <= 0:
        print("[!] Timeout must be a positive number of seconds.")
        return 1
    if args.resolver_workers <= 0:
        print("[!] Resolver workers must be a positive number.")
        return 1

    target = args.target.strip()
    if not target:
        print("[!] Target cannot be empty.")
        return 1

    output_folder = create_output_folder(target)
    print(f"[*] Output folder: {output_folder}")

    if args.keep_raw:
        print("[*] Raw output files will be kept in the output folder.")
    else:
        print("[*] Raw output files are saved in the output folder for review.")

    tools = check_tools()

    if is_ip_address(target):
        run_ip_mode(target, output_folder, args.output, tools, args.timeout, args.debug)
    else:
        domain = normalize_domain(target)
        if not validate_domain(domain):
            print(f"[!] Target does not look like a valid root domain: {target}")
            return 1
        wordlist = validate_wordlist(args.wordlist)
        run_domain_mode(
            domain,
            output_folder,
            args.output,
            tools,
            wordlist,
            args.timeout,
            args.resolver_workers,
            args.debug,
            args.skip_apis,
            args.bbot_full,
        )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting cleanly.")
        sys.exit(130)
