import requests
import argparse
import sys
import os
import signal
import json
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from datetime import datetime
import threading
import time
import base64
from queue import Queue
import pickle
import hashlib


# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Fake User Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0"
]

# Checkpoint Configuration
CHECKPOINT_FILE = "scan_checkpoint.pkl"
CHECKPOINT_INTERVAL = 30  # Save checkpoint every 30 seconds

# Global flag for signal handling
shutdown_requested = False

# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    global shutdown_requested
    if not shutdown_requested:
        shutdown_requested = True
        signal_name = "SIGINT (Ctrl+C)" if signum == signal.SIGINT else "SIGTERM"
        print(f"\n{Colors.YELLOW}[!] Received {signal_name}. Saving checkpoint and exiting gracefully...{Colors.END}")
        # Re-raise KeyboardInterrupt to break out of loops
        raise KeyboardInterrupt()

# Create output directory function
def ensure_output_dir(directory):
    """Create output directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        return True
    return False

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ==================== OPTIMIZED CHECKPOINT MANAGER ====================

class CheckpointManager:
    def __init__(self, checkpoint_file=CHECKPOINT_FILE):
        self.checkpoint_file = checkpoint_file
        self.lock = threading.Lock()
        self.last_save_time = time.time()
        
    def save_checkpoint(self, data):
        """Save checkpoint data to file"""
        with self.lock:
            try:
                # Optimize: Save only what's needed
                processed_data = {
                    'counters': data.get('counters', {}),
                    'processed_url_hashes': list(data.get('processed_url_hashes', set())),
                    'timestamp': time.time()
                }
                
                # Use high-performance pickle protocol
                temp_file = self.checkpoint_file + ".tmp"
                with open(temp_file, 'wb') as f:
                    pickle.dump(processed_data, f, protocol=5 if hasattr(pickle, 'DEFAULT_PROTOCOL') else pickle.HIGHEST_PROTOCOL)
                
                # Atomic replace
                if os.path.exists(self.checkpoint_file):
                    os.remove(self.checkpoint_file)
                os.rename(temp_file, self.checkpoint_file)
                
                return True
            except Exception as e:
                print(f"{Colors.RED}[!] Failed to save checkpoint: {e}{Colors.END}")
                return False
                
    def load_checkpoint(self):
        """Load checkpoint data from file"""
        if not os.path.exists(self.checkpoint_file):
            return None
            
        try:
            with open(self.checkpoint_file, 'rb') as f:
                data = pickle.load(f)
            
            # Convert list back to set for fast lookups
            if 'processed_url_hashes' in data:
                data['processed_url_hashes'] = set(data['processed_url_hashes'])
            
            return data
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load checkpoint: {e}{Colors.END}")
            return None
            
    def should_save_checkpoint(self):
        """Check if it's time to save checkpoint"""
        current_time = time.time()
        if current_time - self.last_save_time >= CHECKPOINT_INTERVAL:
            self.last_save_time = current_time
            return True
        return False
            
    def delete_checkpoint(self):
        """Delete checkpoint file"""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
                return True
        except:
            pass
        return False

# ==================== OPTIMIZED LIVE OUTPUT ====================

class LiveOutput:
    def __init__(self, output_dir, checkpoint_manager=None, resume=False):
        self.lock = threading.Lock()
        self.results = Queue(maxsize=10000)  # Prevent memory overflow
        self.counters = {
            'total': 0,
            'processed': 0,
            'wordpress': 0,
            'joomla': 0,
            'moodle': 0,
            'drupal': 0,
            'unknown': 0,
            'error': 0,
            'vulnerable': 0,
            'vscode_sftp': 0,
            'env_exposed': 0,
            'git_exposed': 0
        }
        self.start_time = time.time()
        self.output_dir = output_dir
        self.last_save_time = time.time()
        self.save_interval = 5  # Save to file every 5 seconds
        self.checkpoint_manager = checkpoint_manager
        self.processed_urls = set()  # Track processed URLs for resume
        self.resume_mode = resume
        self.file_handles = {}  # Keep file handles open for performance
        
        # Create output directory immediately
        ensure_output_dir(output_dir)

        # Initialize result files
        self.result_files = {
            "WordPress": os.path.join(output_dir, "WordPress.txt"),
            "Joomla": os.path.join(output_dir, "Joomla.txt"),
            "Moodle": os.path.join(output_dir, "Moodle.txt"),
            "Drupal": os.path.join(output_dir, "Drupal.txt"),
            "Moodle_Shell_Vulnerable": os.path.join(output_dir, "Moodle_Shell_Vulnerable.txt"),
            "Valid_Sftp": os.path.join(output_dir, "Valid_Sftp.txt"),
            "Env": os.path.join(output_dir, "Env.txt"),
            "Git_Exposed": os.path.join(output_dir, "Git_Exposed.txt"),
            "Unknown_CMS": os.path.join(output_dir, "Unknown_CMS.txt"),
            "Errors": os.path.join(output_dir, "Errors.txt")
        }

        # Open all files once and keep handles
        file_mode = 'a' if resume else 'w'
        for file_key, filepath in self.result_files.items():
            try:
                f = open(filepath, file_mode, buffering=8192)  # 8KB buffer for performance
                if not resume:
                    f.write(f"# {file_key}\n")
                    f.write(f"# Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("#" * 60 + "\n\n")
                self.file_handles[file_key] = f
            except Exception as e:
                print(f"{Colors.RED}[!] Error opening {filepath}: {e}{Colors.END}")

        print(f"{Colors.GREEN}[✓] Output directory ready: {os.path.abspath(output_dir)}{Colors.END}")
        if resume:
            print(f"{Colors.YELLOW}[!] Resume mode enabled{Colors.END}")

    def mark_url_processed(self, url):
        """Mark URL as processed"""
        with self.lock:
            self.processed_urls.add(url)
            
    def is_url_processed(self, url):
        """Check if URL was already processed"""
        with self.lock:
            return url in self.processed_urls

    def update_counter(self, counter):
        with self.lock:
            if counter in self.counters:
                self.counters[counter] += 1
            self.counters['processed'] += 1

    def add_result(self, result_type, url, details=""):
        # Don't block if queue is full
        try:
            self.results.put_nowait((result_type, url, details, time.time()))
        except:
            pass  # Drop result if queue is full (shouldn't happen with 10k size)

        # Auto-save periodically
        current_time = time.time()
        if current_time - self.last_save_time > self.save_interval:
            self.save_to_files()

    def get_stats(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            processed = self.counters['processed']
            speed = processed / elapsed if elapsed > 0 else 0
            return {
                **self.counters,
                'elapsed': elapsed,
                'speed': speed
            }

    def save_to_files(self):
        """Save current results to files - optimized version"""
        try:
            # Process up to 1000 results at a time
            processed = 0
            while not self.results.empty() and processed < 1000:
                try:
                    result_type, url, details, timestamp = self.results.get_nowait()
                    
                    # Map result type to file key
                    file_map = {
                        'wordpress': 'WordPress',
                        'joomla': 'Joomla',
                        'moodle': 'Moodle',
                        'drupal': 'Drupal',
                        'vulnerable_moodle': 'Moodle_Shell_Vulnerable',
                        'vscode_sftp': 'Valid_Sftp',
                        'env_exposed': 'Env',
                        'git_exposed': 'Git_Exposed',
                        'error': 'Errors',
                        'unknown': 'Unknown_CMS'
                    }
                    
                    file_key = file_map.get(result_type.lower())
                    if file_key and file_key in self.file_handles:
                        f = self.file_handles[file_key]
                        if details:
                            f.write(f"{url} | {details}\n")
                        else:
                            f.write(f"{url}\n")
                    
                    processed += 1
                except:
                    break
            
            self.last_save_time = time.time()
            
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error saving results: {e}{Colors.END}")

    def print_live_stats(self):
        stats = self.get_stats()
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(stats['elapsed']))

        sys.stdout.write("\r" + " " * 150 + "\r")  # Clear line

        if stats['total'] > 0:
            progress = (stats['processed'] / stats['total']) * 100
            bar_length = 30
            filled = int(bar_length * progress / 100)
            bar = "█" * filled + "░" * (bar_length - filled)
            sys.stdout.write(f"[{bar}] {progress:5.1f}% | ")

        sys.stdout.write(f"⏱️ {elapsed_str} | 📊 {stats['processed']}/{stats['total']} | ")
        sys.stdout.write(f"🚀 {stats['speed']:.1f}/s | ")

        # Show counters
        if stats['wordpress'] > 0:
            sys.stdout.write(f"WP:{stats['wordpress']} ")
        if stats['joomla'] > 0:
            sys.stdout.write(f"JM:{stats['joomla']} ")
        if stats['moodle'] > 0:
            sys.stdout.write(f"MD:{stats['moodle']} ")
        if stats['drupal'] > 0:
            sys.stdout.write(f"DR:{stats['drupal']} ")
        if stats['vulnerable'] > 0:
            sys.stdout.write(f"🔥:{stats['vulnerable']} ")
        if stats['vscode_sftp'] > 0:
            sys.stdout.write(f"📁:{stats['vscode_sftp']} ")
        if stats['env_exposed'] > 0:
            sys.stdout.write(f"🔑:{stats['env_exposed']} ")
        if stats['git_exposed'] > 0:
            sys.stdout.write(f"🐙:{stats['git_exposed']} ")

        # Show checkpoint indicator
        if self.checkpoint_manager and self.checkpoint_manager.should_save_checkpoint():
            sys.stdout.write(f" 💾")

        sys.stdout.flush()

    def final_save(self):
        """Final save and create summary"""
        # Flush all remaining results
        self.save_to_files()
        
        # Close all file handles
        for f in self.file_handles.values():
            try:
                f.flush()
                f.close()
            except:
                pass
        
        # Create summary file
        summary_file = os.path.join(self.output_dir, f"SCAN_SUMMARY_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        stats = self.get_stats()

        try:
            with open(summary_file, 'w') as f:
                f.write("CMS & VULNERABILITY SCAN SUMMARY REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total URLs: {stats['total']}\n")
                f.write(f"Processed: {stats['processed']}\n")
                f.write(f"Remaining: {stats['total'] - stats['processed']}\n")
                f.write(f"Duration: {time.strftime('%H:%M:%S', time.gmtime(stats['elapsed']))}\n")
                f.write(f"Speed: {stats['speed']:.1f} URLs/second\n")
                f.write(f"Mode: {'Resume' if self.resume_mode else 'Fresh'}\n")
                f.write("-" * 60 + "\n\n")

                f.write("RESULTS BREAKDOWN:\n")
                f.write("-" * 60 + "\n")
                categories = ['wordpress', 'joomla', 'moodle', 'drupal', 'vulnerable',
                            'vscode_sftp', 'env_exposed', 'git_exposed', 'unknown', 'error']
                for category in categories:
                    if stats[category] > 0:
                        f.write(f"{category.replace('_', ' ').title()}: {stats[category]}\n")

            return summary_file

        except Exception as e:
            print(f"{Colors.RED}[!] Error creating summary: {e}{Colors.END}")
            return None

    def __del__(self):
        """Destructor to ensure files are closed"""
        for f in self.file_handles.values():
            try:
                f.close()
            except:
                pass

# ==================== OPTIMIZED REQUESTS SESSION ====================

class OptimizedSession:
    def __init__(self):
        self.session = requests.Session()
        # Optimize connection pooling
        self.session.mount('http://', requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=2
        ))
        self.session.mount('https://', requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=2
        ))
        self.session.verify = False
        self.timeout = 10
        
    def get(self, url, **kwargs):
        headers = kwargs.get('headers', {})
        if 'User-Agent' not in headers:
            headers['User-Agent'] = get_random_user_agent()
        kwargs['headers'] = headers
        kwargs['timeout'] = self.timeout
        return self.session.get(url, **kwargs)
    
    def close(self):
        self.session.close()

# ==================== OPTIMIZED URL PROCESSING ====================

def read_urls_in_chunks(file_path, chunk_size=100000):
    """Read URLs in chunks to save memory"""
    with open(file_path, 'r') as f:
        chunk = []
        for line in f:
            url = normalize_url(line.strip())
            if url:
                chunk.append(url)
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
        if chunk:
            yield chunk

def normalize_url(url):
    """Ensure URL starts with http:// or https://"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

def get_random_user_agent():
    """Return a random user agent from the list"""
    import random
    return random.choice(USER_AGENTS)

# ==================== CMS DETECTION PATTERNS ====================

CMS_PATTERNS = {
    "WordPress": [
        (r'<meta name="generator" content="WordPress', 'meta'),
        (r'wp-content', 'path'),
        (r'wp-includes', 'path'),
        (r'/wp-json/', 'path'),
        (r'/wp-admin/', 'path'),
        (r'wordpress', 'html'),
        (r'<link rel=["\']stylesheet["\'] href=["\'][^"\']*wp-content', 'link'),
        (r'<script src=["\'][^"\']*wp-includes', 'script'),
    ],
    "Joomla": [
        (r'<meta name="generator" content="Joomla', 'meta'),
        (r'joomla', 'html'),
        (r'Joomla', 'html'),
        (r'/media/joomla/', 'path'),
        (r'/media/system/', 'path'),
        (r'/components/com_', 'path'),
    ],
    "Moodle": [
        (r'<meta name="keywords" content="moodle', 'meta'),
        (r'moodle', 'html'),
        (r'Moodle', 'html'),
        (r'/theme/styles.php', 'path'),
        (r'/lib/javascript.php', 'path'),
        (r'/login/index.php', 'path'),
    ],
    "Drupal": [
        (r'<meta name="Generator" content="Drupal', 'meta'),
        (r'drupal', 'html'),
        (r'Drupal', 'html'),
        (r'/sites/all/', 'path'),
        (r'/sites/default/', 'path'),
        (r'/modules/', 'path'),
    ],
}

# ==================== VULNERABILITY CHECKS ====================

def check_moodle_shell(url, session, timeout=8):
    """Check for Moodle webshell vulnerability"""
    try:
        path = "/local/moodle_webshell/webshell0.php?action=exec&cmd=echo \"Nullhaxor\""
        full_url = urljoin(url, path)

        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "application/json, text/html, */*"
        }

        response = session.get(full_url, headers=headers, allow_redirects=True)

        # Fast check
        if '"stdout"' in response.text and 'Nullhaxor' in response.text:
            return True, response.status_code, len(response.text)

        return False, response.status_code, len(response.text)

    except Exception:
        return False, 0, 0

def check_vscode_sftp(url, session, timeout=8):
    """Check for exposed VSCode SFTP configuration"""
    try:
        path = "/.vscode/sftp.json"
        full_url = urljoin(url, path)

        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "application/json, */*"
        }

        response = session.get(full_url, headers=headers, allow_redirects=True)

        if response.status_code == 200:
            content = response.text.strip()
            # Quick JSON check
            if '"name"' in content and '"host"' in content and '"username"' in content:
                return True, response.status_code, len(response.text), "Found"

        return False, response.status_code, len(response.text), None

    except Exception:
        return False, 0, 0, None

def check_env_exposed(url, session, timeout=8):
    """Check for exposed .env file with APP_KEY"""
    try:
        path = "/.env"
        full_url = urljoin(url, path)

        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/plain, */*"
        }

        response = session.get(full_url, headers=headers, allow_redirects=True)

        if response.status_code == 200:
            content = response.text
            # Fast pattern check
            if 'APP_KEY' in content or 'DB_PASSWORD' in content or 'SECRET_KEY' in content:
                return True, response.status_code, len(response.text), "Sensitive data found"

        return False, response.status_code, len(response.text), None

    except Exception:
        return False, 0, 0, None

def check_git_exposed(url, session, timeout=8):
    """Check for exposed .git directory"""
    try:
        path = "/.git/config"
        full_url = urljoin(url, path)

        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/plain, */*"
        }

        response = session.get(full_url, headers=headers, allow_redirects=True)

        if response.status_code == 200:
            content = response.text
            if '[core]' in content or 'repositoryformatversion' in content:
                return True, response.status_code, len(response.text), "Git exposed"

        return False, response.status_code, len(response.text), None

    except Exception:
        return False, 0, 0, None

# ==================== OPTIMIZED DETECTION FUNCTION ====================

def detect_cms_and_vulnerabilities(url, output_manager=None):
    """Optimized detection function"""
    results = {
        'cms': None,
        'moodle_shell': False,
        'vscode_sftp': False,
        'env_exposed': False,
        'git_exposed': False
    }
    
    # Create session for this URL
    session = OptimizedSession()
    
    try:
        # Check CMS
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        response = session.get(url, headers=headers, allow_redirects=True)
        
        if response.status_code == 200:
            html_content = response.text.lower()
            
            # Fast CMS detection
            if 'wordpress' in html_content or 'wp-content' in html_content or 'wp-includes' in html_content:
                results['cms'] = "WordPress"
            elif 'joomla' in html_content or '/media/joomla/' in html_content:
                results['cms'] = "Joomla"
            elif 'moodle' in html_content or '/theme/styles.php' in html_content:
                results['cms'] = "Moodle"
                # Check Moodle shell if it's Moodle
                is_vulnerable, _, _ = check_moodle_shell(url, session)
                if is_vulnerable:
                    results['moodle_shell'] = True
            elif 'drupal' in html_content or '/sites/' in html_content:
                results['cms'] = "Drupal"
            
            # Update CMS counter
            if output_manager and results['cms']:
                output_manager.update_counter(results['cms'].lower())
        
        # Check vulnerabilities in parallel but with timeout
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Only check some vulnerabilities if not already found CMS
            if not results['moodle_shell']:
                futures['vscode_sftp'] = executor.submit(check_vscode_sftp, url, session)
                futures['env_exposed'] = executor.submit(check_env_exposed, url, session)
                futures['git_exposed'] = executor.submit(check_git_exposed, url, session)
            
            for vuln_type, future in futures.items():
                try:
                    if vuln_type == 'vscode_sftp':
                        is_found, _, _, _ = future.result(timeout=3)
                        if is_found:
                            results[vuln_type] = True
                            if output_manager:
                                output_manager.update_counter('vscode_sftp')
                    elif vuln_type == 'env_exposed':
                        is_found, _, _, _ = future.result(timeout=3)
                        if is_found:
                            results[vuln_type] = True
                            if output_manager:
                                output_manager.update_counter('env_exposed')
                    elif vuln_type == 'git_exposed':
                        is_found, _, _, _ = future.result(timeout=3)
                        if is_found:
                            results[vuln_type] = True
                            if output_manager:
                                output_manager.update_counter('git_exposed')
                except:
                    pass
        
    except Exception:
        pass
    finally:
        session.close()
    
    return results

# ==================== MAIN FUNCTION ====================

def banner():
    """Display banner"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}ULTIMATE WEB SCANNER - OPTIMIZED FOR VPS{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.WHITE}WordPress  {Colors.BLUE}█{Colors.END}  Joomla  {Colors.GREEN}█{Colors.END}  Moodle  {Colors.YELLOW}█{Colors.END}  Drupal  {Colors.MAGENTA}█{Colors.END}")
    print(f"{Colors.WHITE}VSCode SFTP  {Colors.CYAN}📁{Colors.END}  .env Exposed  {Colors.RED}🔑{Colors.END}  Git Exposed  {Colors.YELLOW}🐙{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="Ultimate Web Scanner - Optimized for VPS")
    parser.add_argument("-l", "--list", required=True, help="File containing list of URLs")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-o", "--output", default="scan_results", help="Output directory")
    parser.add_argument("--resume", action="store_true", help="Resume from previous checkpoint")
    parser.add_argument("--no-checkpoint", action="store_true", help="Disable checkpoint saving")

    args = parser.parse_args()

    banner()

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Count total URLs
    print(f"{Colors.WHITE}[*] Counting URLs in {args.list}...{Colors.END}")
    total_urls = 0
    try:
        with open(args.list, 'r') as f:
            for line in f:
                if line.strip():
                    total_urls += 1
    except FileNotFoundError:
        print(f"{Colors.RED}[-] File not found: {args.list}{Colors.END}")
        sys.exit(1)

    if total_urls == 0:
        print(f"{Colors.RED}[-] No URLs found{Colors.END}")
        sys.exit(1)

    # Initialize checkpoint manager
    checkpoint_manager = None if args.no_checkpoint else CheckpointManager()
    
    # Initialize output manager
    output_manager = LiveOutput(args.output, checkpoint_manager, args.resume)
    output_manager.counters['total'] = total_urls
    
    # Load checkpoint if resuming
    processed_url_hashes = set()
    
    if args.resume and checkpoint_manager:
        checkpoint_data = checkpoint_manager.load_checkpoint()
        if checkpoint_data:
            processed_url_hashes = checkpoint_data.get('processed_url_hashes', set())
            # Load counters
            if 'counters' in checkpoint_data:
                output_manager.counters.update(checkpoint_data['counters'])
            
            print(f"{Colors.YELLOW}[!] Resuming: {len(processed_url_hashes)} URLs already processed{Colors.END}")

    print(f"{Colors.WHITE}[*] Target File: {args.list}")
    print(f"[*] Total URLs: {total_urls:,}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Output Directory: {os.path.abspath(args.output)}")
    print(f"[*] Checkpoint: {'Enabled' if not args.no_checkpoint else 'Disabled'}")
    print(f"[*] Start Time: {datetime.now().strftime('%H:%M:%S')}{Colors.END}")
    print(f"{Colors.CYAN}{'-'*70}{Colors.END}")

    # Process URLs in chunks
    try:
        chunk_num = 0
        for url_chunk in read_urls_in_chunks(args.list, chunk_size=100000):
            chunk_num += 1
            print(f"\n{Colors.YELLOW}[!] Processing chunk {chunk_num} ({len(url_chunk):,} URLs){Colors.END}")
            
            # Filter out already processed URLs
            urls_to_process = []
            for url in url_chunk:
                url_hash = hashlib.md5(url.encode()).hexdigest()
                if url_hash not in processed_url_hashes:
                    urls_to_process.append(url)
                else:
                    output_manager.counters['processed'] += 1
            
            if not urls_to_process:
                print(f"{Colors.YELLOW}[!] All URLs in chunk already processed{Colors.END}")
                continue
            
            # Process this chunk
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {}
                for url in urls_to_process:
                    if shutdown_requested:
                        break
                    futures[executor.submit(detect_cms_and_vulnerabilities, url, output_manager)] = url
                
                for future in as_completed(futures):
                    if shutdown_requested:
                        break
                    
                    url = futures[future]
                    try:
                        results = future.result(timeout=15)
                        
                        # Mark as processed
                        url_hash = hashlib.md5(url.encode()).hexdigest()
                        processed_url_hashes.add(url_hash)
                        
                        # Add results
                        if results['moodle_shell']:
                            output_manager.add_result("vulnerable_moodle", url, "Moodle Shell")
                        elif results['vscode_sftp']:
                            output_manager.add_result("vscode_sftp", url, "VSCode SFTP")
                        elif results['env_exposed']:
                            output_manager.add_result("env_exposed", url, "Env Exposed")
                        elif results['git_exposed']:
                            output_manager.add_result("git_exposed", url, "Git Exposed")
                        elif results['cms']:
                            output_manager.add_result(results['cms'].lower(), url, results['cms'])
                        
                        # Update live stats
                        output_manager.print_live_stats()
                        
                    except Exception as e:
                        # Silently skip errors
                        pass
                    
                    # Save checkpoint periodically
                    if checkpoint_manager and checkpoint_manager.should_save_checkpoint():
                        checkpoint_data = {
                            'counters': output_manager.counters.copy(),
                            'processed_url_hashes': processed_url_hashes
                        }
                        checkpoint_manager.save_checkpoint(checkpoint_data)
            
            # Save checkpoint after each chunk
            if checkpoint_manager and not shutdown_requested:
                checkpoint_data = {
                    'counters': output_manager.counters.copy(),
                    'processed_url_hashes': processed_url_hashes
                }
                checkpoint_manager.save_checkpoint(checkpoint_data)
            
            if shutdown_requested:
                break

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted{Colors.END}")
    
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}")
    
    finally:
        # Final save
        print(f"\n{Colors.GREEN}[+] Saving final results...{Colors.END}")
        summary_file = output_manager.final_save()
        
        # Save final checkpoint
        if checkpoint_manager:
            checkpoint_data = {
                'counters': output_manager.counters.copy(),
                'processed_url_hashes': processed_url_hashes
            }
            checkpoint_manager.save_checkpoint(checkpoint_data)
        
        # Show final stats
        stats = output_manager.get_stats()
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}SCAN COMPLETED{Colors.END}")
        print(f"{Colors.CYAN}{'-'*70}{Colors.END}")
        print(f"{Colors.WHITE}Duration: {time.strftime('%H:%M:%S', time.gmtime(stats['elapsed']))}")
        print(f"Processed: {stats['processed']:,}/{total_urls:,}")
        print(f"Speed: {stats['speed']:.1f} URLs/second{Colors.END}")
        
        if summary_file:
            print(f"\n{Colors.GREEN}[✓] Summary: {summary_file}{Colors.END}")
        
        if checkpoint_manager and os.path.exists(CHECKPOINT_FILE):
            print(f"{Colors.YELLOW}[!] Checkpoint saved. Use --resume to continue.{Colors.END}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")

if __name__ == "__main__":
    main()
