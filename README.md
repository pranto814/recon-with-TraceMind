```text
 _____                   __  __ _           _
|_   _| __ __ _  ___ ___|  \/  (_)_ __   __| |
  | || '__/ _` |/ __/ _ \ |\/| | | '_ \ / _` |
  | || | | (_| | (_|  __/ |  | | | | | | (_| |
  |_||_|  \__,_|\___\___|_|  |_|_|_| |_|\__,_|

TraceMind - Maximum Subdomain Discovery Tool
A simple, modern subdomain discovery and DNS reconnaissance tool.
```



# TraceMind

TraceMind is a Linux/Kali command-line cybersecurity reconnaissance tool written in Python 3.
It is designed for authorized DNS reconnaissance only: subdomain discovery, DNS enumeration, DNS resolution, and clean result saving.

Use this tool only on domains/IPs you own or have permission to test.

## What TraceMind Does

TraceMind combines output from public/open recon tools and passive sources, removes duplicates, extracts valid subdomains for the target root domain, resolves each hostname to IP addresses, and saves a final TXT report.

Core local tools:

- `subfinder`
- `sublist3r`
- `amass`
- `dnsrecon`
- `theHarvester`
- `dig`
- `host`

Optional public local tools:

- `bbot`
- `findomain`
- `knockpy`
- `darkscout`

Built-in passive web/API sources:

- crt.sh
- AlienVault OTX
- ThreatMiner
- HackerTarget
- AnubisDB
- SecurityTrails, only when `SECURITYTRAILS_API_KEY` is set
- DNSDumpster official API, only when `DNSDUMPSTER_API_KEY` is set
- Shodan DNS/domain lookup and host search, only when `SHODAN_API_KEY` is set

TraceMind does not include Censys, direct C99 API, or Pentest-Tools cloud scanning in this final public-use build because those are token/plan/paid/quota-dependent and can confuse setup.

No public recon tool can guarantee every subdomain. The only reliable way to know all DNS names is direct access to the target's authoritative DNS zone data. TraceMind is best-effort and combines many sources to improve coverage.

## Installation

Clone or copy this project, then install the Python dependency and make the script executable:

```bash
pip3 install -r requirements.txt
chmod +x tracemind.py
```

If `dnspython` is not installed, TraceMind falls back to `dig` and `host` for DNS resolution.

## Optional Kali Installation

```bash
sudo apt update
sudo apt install subfinder sublist3r amass dnsrecon theharvester dnsutils seclists findomain -y
```

Some Kali package names and availability can vary by release. If a tool is missing, install it from that tool's official instructions.

## Optional Tool Installation

Install `pipx` first if it is not already available:

```bash
sudo apt install pipx -y
pipx ensurepath
```

Close and reopen the terminal after `pipx ensurepath` if the installed commands are not found.

`pipx` normally installs commands into:

```bash
/home/kali/.local/bin
```

That is normal. TraceMind checks both your normal `PATH` and common Kali locations like `/home/kali/.local/bin` and `/usr/local/bin`. If your shell still cannot find a `pipx` command, add this line to `~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload the terminal:

```bash
source ~/.bashrc
hash -r
```

Install BBOT:

```bash
pipx install bbot
bbot --help
```

Install Findomain:

```bash
sudo apt install findomain -y
findomain --help
```

If Kali cannot find the `findomain` package, use the official release binary:

```bash
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/findomain
findomain --help
```

Install Knockpy:

```bash
pipx install git+https://github.com/guelfoweb/knock.git
knockpy --help
```

Install DarkScout:

```bash
sudo apt install git cargo -y
git clone https://github.com/DarkSuite/DarkScout
cd DarkScout
cargo build --release
sudo cp target/release/DarkScout /usr/local/bin/darkscout
darkscout --help
```

Confirm TraceMind can detect the optional tools:

```bash
which bbot
which findomain
which knockpy
which darkscout
python3 -c 'import shutil; print(shutil.which("bbot")); print(shutil.which("knockpy"))'
```

```bash
sudo cp /home/kali/.local/bin/bbot /usr/local/bin/bbot
sudo cp /home/kali/.local/bin/knockpy /usr/local/bin/knockpy
sudo chmod +x /usr/local/bin/bbot /usr/local/bin/knockpy
hash -r
```


## API Keys

TraceMind works without API keys. These optional public signup APIs are used only when the matching environment variable exists:

```bash
export SECURITYTRAILS_API_KEY="your_key"
export DNSDUMPSTER_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
```

Paste these `export` commands in your Kali terminal before running TraceMind. For permanent use, add them to the bottom of `~/.bashrc` and run `source ~/.bashrc`.

Never share screenshots or messages containing real API keys.

## Shodan Support

TraceMind can use Shodan as a passive source when `SHODAN_API_KEY` is set.

It uses:

- Shodan DNS domain lookup to collect known subdomain labels
- Shodan host search with `hostname:<domain>` to collect hostnames seen in Shodan data

TraceMind does not start Shodan on-demand scans. Shodan API usage can consume account query credits depending on your plan.

Set your key in Kali:

```bash
export SHODAN_API_KEY="your_shodan_api_key"
```

Then run TraceMind normally:

```bash
python3 tracemind.py -t example.com
```

Shodan raw outputs:

- `raw_shodan_domain.txt`
- `raw_shodan_search.txt`

## Usage Examples

Basic domain scan:

```bash
python3 tracemind.py -t example.com
```

Choose the final output file name:

```bash
python3 tracemind.py -t example.com -o final.txt
```

Use a brute-force wordlist:

```bash
python3 tracemind.py -t example.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

Use more resolver threads:

```bash
python3 tracemind.py -t example.com --resolver-workers 50
```

Run BBOT's full subdomain-enum preset instead of the default passive-only BBOT mode:

```bash
python3 tracemind.py -t example.com --bbot-full
```

Skip built-in web/API sources:

```bash
python3 tracemind.py -t example.com --skip-apis
```

Run IP mode:

```bash
python3 tracemind.py -t 192.168.1.10 -o ip_result.txt
```

Show detailed command errors:

```bash
python3 tracemind.py -t example.com --debug
```

## Domain Mode

When the target is a domain, TraceMind runs the installed tools it can find and skips missing tools without crashing.

The original pipeline still runs:

- `subfinder -d <domain> -all -silent -o raw_subfinder.txt`
- `sublist3r -d <domain> -o raw_sublist3r.txt`
- `amass enum -passive -d <domain> -o raw_amass_passive.txt`
- `amass enum -brute -d <domain> -o raw_amass_brute.txt`
- `dnsrecon -d <domain> -a -k`
- `dnsrecon -d <domain> -D <wordlist> -t brt` when a wordlist is provided
- `theHarvester` with many individual sources, including `dnsdumpster` and `subdomainfinderc99`
- A best-effort `theHarvester -d <domain> -b all -c` attempt

The stronger public-use pipeline adds:

- BBOT subdomain enumeration, if installed
- Findomain, if installed
- DarkScout, if installed
- Knockpy, if installed
- Built-in passive API collection from public sources
- SecurityTrails, DNSDumpster, and Shodan, if you set their keys

Aquatone is not used as a discovery source because it is mainly for probing and screenshotting already-discovered live web services. You can feed TraceMind's `clean_subdomains.txt` into Aquatone after enumeration if you want visual recon.

## IP Mode

When the target is an IP address, TraceMind performs reverse DNS/PTR lookup using:

- `socket.gethostbyaddr()`
- `dig -x <ip> +short`
- `host <ip>`

IP mode saves output like:

```text
hostname.example.com : 192.168.1.10
```

If no PTR record is found:

```text
No PTR hostname found : 192.168.1.10
```

IP mode is limited. For maximum subdomain discovery, provide the root domain.

## Output Format

Final output is saved like this:

```text
www.example.com : 93.184.216.34
mail.example.com : 93.184.216.35
dev.example.com : No IP found
```

If a subdomain resolves to multiple IPs, TraceMind writes one line per IP.

## Output Folder

TraceMind automatically creates a timestamped output folder:

```text
tracemind_<target>_<timestamp>/
```

Common files inside that folder:

- `raw_subfinder.txt`
- `raw_sublist3r.txt`
- `raw_amass_passive.txt`
- `raw_amass_brute.txt`
- `raw_dnsrecon.txt`
- `raw_dnsrecon_brute.txt`
- `raw_theharvester_<source>.txt`
- `raw_theharvester_all_brute.txt`
- `raw_bbot.txt`
- `raw_findomain.txt`
- `raw_darkscout.txt`
- `raw_knockpy.txt`
- `raw_securitytrails.txt`
- `raw_dnsdumpster.txt`
- `raw_shodan_domain.txt`
- `raw_shodan_search.txt`
- `raw_public_<source>.txt`
- `all_raw.txt`
- `clean_subdomains.txt`
- `final_subdomains_with_ip.txt`

If you pass `-o final.txt`, the final report is saved with that file name inside the TraceMind output folder.

## Ethics Warning

TraceMind is for authorized reconnaissance only.

Do not use it for exploitation, vulnerability scanning, password attacks, brute forcing login pages, or any activity you do not have permission to perform.
