#!/usr/bin/env python3

import os
import sys
import time
import argparse
import signal
import subprocess
import base64
import hashlib
import threading
import shutil
from datetime import datetime, time as dt_time
from pathlib import Path
from typing import Optional, Dict, Set, List

# Default configuration - Log Monitoring
DEFAULT_IP = "74.162.152.133"
DEFAULT_PORT = 514
DEFAULT_FILE1 = "/usr/sap/S4T/D00/work/dev_icm"
DEFAULT_FILE2 = "/tmp/system_logs.json"
DEFAULT_FILE3 = "/tmp/sal_export.json"
DEFAULT_FILE4 = "/tmp/sap_version.json"
DEFAULT_DATE_BASED_DIR = "/usr/sap/S4T/D00/log"
DEFAULT_DATE_BASED_PREFIX = "gw_log-S4T-faplh-"
DEFAULT_POSITION_DIR = "/home/admin1/.log_monitor_positions"

# Default configuration - SAP to Wazuh
DEFAULT_SAP_INPUT_FILE = "/tmp/encrypt_benchmark.xml"
DEFAULT_SAP_LOCAL_OUT = "/home/admin1/sap_sca_results.txt"
DEFAULT_SAP_LOCAL_TEMP = "/home/admin1/sap_sca_results_temp.txt"
DEFAULT_SAP_HASH_FILE = "/home/admin1/.sap_sca_last_hash"
DEFAULT_SAP_LOG_FILE = "/home/admin1/sap_monitor.log"
DEFAULT_WAZUH_USER = "demo"
DEFAULT_WAZUH_HOST = "154.57.212.220"
DEFAULT_WAZUH_PORT = 81
DEFAULT_WAZUH_SAP_DIR = "/var/ossec/sap"
DEFAULT_WAZUH_TEMP_DIR = "/home/demo"
DEFAULT_WAZUH_PASS = "demo"
DEFAULT_CHECK_INTERVAL = 10
DEFAULT_STABLE_WAIT = 3

# Default keywords to skip in SAP processing
DEFAULT_SKIP_KEYWORDS = [
    "CATALOG_READ_Privilege",
    "TRACE_ADMIN_Privilege",
    "CONTENT_ADMIN_Role",
    "SAP_INTERNAL_HANA_SUPPORT_Role",
    "INIFILE_ADMIN_Privilege",
    "SERVICE_ADMIN_Privilege",
    "LICENSE_ADMIN_Privilege",
    "LOG_ADMIN_Privilege",
    "TRUST_ADMIN_Privilege",
    "IMPORT_EXPORT_Privileges",
    "Encryption_LOG_PERSISTENCE_Status",
    "Active_Network_Services",
    "Session_Configuration"
]

# Color codes for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


class AuditLogDecryptor:
    """Decrypts SAP audit log data encrypted with XOR cipher"""

    def __init__(self):
        # Hidden encryption key (must match ABAP program)
        # Key: "SAP2025SecureAudit!@#$%"
        self._key = bytes([
            0x53, 0x41, 0x50, 0x32, 0x30, 0x32, 0x35, 0x53,
            0x65, 0x63, 0x75, 0x72, 0x65, 0x41, 0x75, 0x64,
            0x69, 0x74, 0x21, 0x40, 0x23, 0x24, 0x25
        ])

    def decrypt_line(self, encrypted_line: str) -> Optional[str]:
        """
        Decrypt a single line of encrypted audit log data

        Args:
            encrypted_line: Base64 encoded encrypted string

        Returns:
            Decrypted JSON string or None if decryption fails
        """
        try:
            # Remove any whitespace
            encrypted_line = encrypted_line.strip()

            if not encrypted_line:
                return None

            # Decode from Base64
            encrypted_bytes = base64.b64decode(encrypted_line)

            # XOR decryption (same as encryption)
            decrypted_bytes = bytearray()
            key_len = len(self._key)

            for i, byte in enumerate(encrypted_bytes):
                key_byte = self._key[i % key_len]
                decrypted_byte = byte ^ key_byte
                decrypted_bytes.append(decrypted_byte)

            # Convert to string
            decrypted_str = decrypted_bytes.decode('utf-8')

            return decrypted_str

        except Exception:
            return None


class SAPWazuhMonitor:
    """Monitor SAP SCA results and transfer to Wazuh server"""

    def __init__(self, input_file: str, local_out: str, local_temp: str,
                 hash_file: str, log_file: str, wazuh_user: str,
                 wazuh_host: str, wazuh_port: int, wazuh_sap_dir: str,
                 wazuh_temp_dir: str, wazuh_pass: str, check_interval: int,
                 stable_wait: int, skip_keywords: List[str]):
        self.input_file = input_file
        self.local_out = local_out
        self.local_temp = local_temp
        self.hash_file = hash_file
        self.log_file = log_file
        self.wazuh_user = wazuh_user
        self.wazuh_host = wazuh_host
        self.wazuh_port = wazuh_port
        self.wazuh_sap_dir = wazuh_sap_dir
        self.wazuh_temp_dir = wazuh_temp_dir
        self.wazuh_pass = wazuh_pass
        self.check_interval = check_interval
        self.stable_wait = stable_wait
        self.skip_keywords = skip_keywords
        self.running = True
        self.last_hash = ""
        self.last_mtime = 0

        # Load last known hash
        self._load_last_hash()

        # Check dependencies
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if required commands are available"""
        required_cmds = ['scp', 'ssh', 'expect']
        missing = []
        
        for cmd in required_cmds:
            if not self._check_command(cmd):
                missing.append(cmd)
        
        if missing:
            self.log_error(f"Missing required commands: {', '.join(missing)}")
            self.log_error("Please install: sudo apt-get install openssh-client expect")
            sys.exit(1)

    @staticmethod
    def _check_command(cmd: str) -> bool:
        """Check if a command is available"""
        try:
            subprocess.run(
                ['which', cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _load_last_hash(self):
        """Load the last known hash from file"""
        try:
            if os.path.exists(self.hash_file):
                with open(self.hash_file, 'r') as f:
                    self.last_hash = f.read().strip()
                    if self.last_hash:
                        self.log_msg(f"Loaded previous hash: {self.last_hash}")
        except IOError:
            pass

    def _save_hash(self, hash_value: str):
        """Save hash to file"""
        try:
            with open(self.hash_file, 'w') as f:
                f.write(hash_value)
        except IOError as e:
            self.log_error(f"Failed to save hash: {e}")

    def log_msg(self, message: str):
        """Log informational messages"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{Colors.CYAN}[{timestamp}] [SAP-WAZUH]{Colors.NC} {message}"
        print(log_line)
        self._write_to_log_file(f"[{timestamp}] {message}")

    def log_error(self, message: str):
        """Log error messages"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{Colors.RED}[{timestamp}] [SAP-WAZUH] ERROR:{Colors.NC} {message}"
        print(log_line, file=sys.stderr)
        self._write_to_log_file(f"[{timestamp}] ERROR: {message}")

    def log_warn(self, message: str):
        """Log warning messages"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{Colors.YELLOW}[{timestamp}] [SAP-WAZUH] WARNING:{Colors.NC} {message}"
        print(log_line)
        self._write_to_log_file(f"[{timestamp}] WARNING: {message}")

    def _write_to_log_file(self, message: str):
        """Write to log file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(message + '\n')
        except IOError:
            pass

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate MD5 hash of a file"""
        try:
            if not os.path.exists(file_path):
                return None
            
            hash_md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except IOError:
            return None

    def wait_for_stable_file(self, file_path: str):
        """Wait until file stops changing"""
        last_size = -1
        stable_count = 0

        while stable_count < self.stable_wait:
            if os.path.exists(file_path):
                try:
                    current_size = os.path.getsize(file_path)
                except OSError:
                    current_size = 0
            else:
                current_size = 0

            if current_size == last_size and current_size > 0:
                stable_count += 1
            else:
                stable_count = 0

            last_size = current_size
            time.sleep(1)

    def process_file(self) -> bool:
        """Process input file - filter keywords and remove duplicates"""
        try:
            if not os.path.exists(self.input_file):
                return False

            # Read input file
            with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Filter out lines containing skip keywords
            filtered_lines = []
            seen = set()

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Check if line contains any skip keyword
                skip = False
                for keyword in self.skip_keywords:
                    if keyword in line:
                        skip = True
                        break

                if not skip and line not in seen:
                    filtered_lines.append(line)
                    seen.add(line)

            # Write to temp file
            if not filtered_lines:
                return False

            with open(self.local_temp, 'w', encoding='utf-8') as f:
                f.write('\n'.join(filtered_lines) + '\n')

            return True

        except IOError as e:
            self.log_error(f"Failed to process file: {e}")
            return False

    def transfer_to_wazuh(self) -> bool:
        """Transfer file to Wazuh server using SCP and SSH"""
        self.log_msg("Transferring file to Wazuh manager...")

        # Create expect script for SCP transfer
        scp_script = f"""#!/usr/bin/expect
set timeout 30
spawn scp -o StrictHostKeyChecking=no -P {self.wazuh_port} "{self.local_out}" "{self.wazuh_user}@{self.wazuh_host}:{self.wazuh_temp_dir}/sap_sca_results.txt"
expect {{
    "password:" {{ send "{self.wazuh_pass}\\r"; exp_continue }}
    "Password:" {{ send "{self.wazuh_pass}\\r"; exp_continue }}
    eof
}}
"""

        try:
            # Execute SCP transfer
            result = subprocess.run(
                ['expect', '-c', scp_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60
            )

            if result.returncode != 0:
                self.log_error("File transfer failed")
                return False

            self.log_msg(f"File uploaded to {self.wazuh_temp_dir}")

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.log_error(f"SCP transfer failed: {e}")
            return False

        # Move file with root privileges
        self.log_msg(f"Moving file to {self.wazuh_sap_dir}...")

        ssh_script = f"""#!/usr/bin/expect
set timeout 30
spawn ssh -p {self.wazuh_port} -o StrictHostKeyChecking=no {self.wazuh_user}@{self.wazuh_host}
expect "password:"
send "{self.wazuh_pass}\\r"
expect "$ "
send "sudo -i\\r"
expect "password"
send "{self.wazuh_pass}\\r"
expect "# "
send "mkdir -p {self.wazuh_sap_dir}\\r"
expect "# "
send "mv {self.wazuh_temp_dir}/sap_sca_results.txt {self.wazuh_sap_dir}/\\r"
expect "# "
send "chown wazuh:wazuh {self.wazuh_sap_dir}/sap_sca_results.txt\\r"
expect "# "
send "chmod 644 {self.wazuh_sap_dir}/sap_sca_results.txt\\r"
expect "# "
send "exit\\r"
expect "$ "
send "exit\\r"
expect eof
"""

        try:
            result = subprocess.run(
                ['expect', '-c', ssh_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60
            )

            if result.returncode != 0:
                self.log_error("Failed to move file to final location")
                return False

            self.log_msg(f"SUCCESS: File transferred to {self.wazuh_sap_dir}/sap_sca_results.txt")
            return True

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.log_error(f"SSH command failed: {e}")
            return False

    def run(self):
        """Main monitoring loop"""
        self.log_msg("Starting SAP to Wazuh continuous monitoring...")
        self.log_msg(f"Monitoring file: {self.input_file}")
        self.log_msg(f"Check interval: {self.check_interval}s")

        while self.running:
            try:
                # Check if file exists
                if not os.path.exists(self.input_file):
                    time.sleep(self.check_interval)
                    continue

                # Get current modification time
                try:
                    current_mtime = os.path.getmtime(self.input_file)
                except OSError:
                    time.sleep(self.check_interval)
                    continue

                # Check if file was modified
                if current_mtime > self.last_mtime:
                    self.log_msg("File modification detected")

                    # Wait for file to stabilize
                    self.wait_for_stable_file(self.input_file)
                    self.log_msg("File appears stable, processing...")

                    # Process the file
                    if self.process_file():
                        # Calculate hash of processed content
                        current_hash = self.get_file_hash(self.local_temp)

                        if current_hash and current_hash != self.last_hash:
                            self.log_msg("New data detected (hash changed)")
                            self.log_msg(f"Previous: {self.last_hash}")
                            self.log_msg(f"Current:  {current_hash}")

                            # Move temp to final
                            try:
                                shutil.move(self.local_temp, self.local_out)
                            except IOError as e:
                                self.log_error(f"Failed to move temp file: {e}")
                                time.sleep(self.check_interval)
                                continue

                            # Transfer to Wazuh
                            if self.transfer_to_wazuh():
                                # Update last known hash
                                self.last_hash = current_hash
                                self._save_hash(self.last_hash)
                                self.log_msg("Hash saved for future comparison")
                        else:
                            self.log_msg("Content unchanged (hash match) - skipping transfer")
                            try:
                                os.remove(self.local_temp)
                            except OSError:
                                pass
                    else:
                        self.log_msg("No valid data after filtering")
                        try:
                            if os.path.exists(self.local_temp):
                                os.remove(self.local_temp)
                        except OSError:
                            pass

                    self.last_mtime = current_mtime

                time.sleep(self.check_interval)

            except Exception as e:
                self.log_error(f"Unexpected error in monitoring loop: {e}")
                time.sleep(self.check_interval)


class LogMonitor:
    def __init__(self, dest_ip: str, dest_port: int, position_dir: str,
                 file1: str, file2: str, file3: str, file4: str,
                 date_based_dir: str, date_based_prefix: str,
                 encrypted_files: set):
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.position_dir = Path(position_dir)
        self.file1 = file1
        self.file2 = file2
        self.file3 = file3
        self.file4 = file4
        self.date_based_dir = date_based_dir
        self.date_based_prefix = date_based_prefix
        self.encrypted_files = encrypted_files
        self.running = True
        self.warned_files: Dict[str, bool] = {}
        self.decryptor = AuditLogDecryptor()
        self.last_reset_date = datetime.now().date()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Check if netcat is available (required)
        if not self._check_command('nc'):
            self.log_error("Required command not found: nc (netcat)")
            self.log_error("Please install netcat: sudo apt-get install netcat")
            sys.exit(1)

        # Create position directory
        try:
            self.position_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.log_error(f"Failed to create position tracking directory: {self.position_dir}")
            sys.exit(1)

    def _check_command(self, cmd: str) -> bool:
        """Check if a command is available"""
        try:
            subprocess.run(
                ['which', cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.log_msg("Shutting down...")
        self.running = False
        sys.exit(0)

    @staticmethod
    def log_msg(message: str):
        """Log informational messages in green"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.GREEN}[{timestamp}]{Colors.NC} {message}")

    @staticmethod
    def log_error(message: str):
        """Log error messages in red"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.RED}[{timestamp}] ERROR:{Colors.NC} {message}", file=sys.stderr)

    @staticmethod
    def log_warn(message: str):
        """Log warning messages in yellow"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.YELLOW}[{timestamp}] WARNING:{Colors.NC} {message}")

    @staticmethod
    def log_info(message: str):
        """Log info messages in blue"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.BLUE}[{timestamp}] INFO:{Colors.NC} {message}")

    @staticmethod
    def log_reset(message: str):
        """Log reset messages in magenta"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{Colors.MAGENTA}[{timestamp}] RESET:{Colors.NC} {message}")

    @staticmethod
    def get_inode(file_path: str) -> int:
        """Get the inode of a file (safe)"""
        try:
            return os.stat(file_path).st_ino
        except (OSError, FileNotFoundError):
            return 0

    @staticmethod
    def get_todays_file(directory: str, prefix: str) -> str:
        """Get today's date-based filename"""
        today = datetime.now().strftime('%Y%m%d')
        return os.path.join(directory, f"{prefix}{today}")

    def send_log_udp(self, log_line: str) -> bool:
        """Send log line via UDP using netcat"""
        try:
            subprocess.run(
                ['nc', '-u', '-w1', self.dest_ip, str(self.dest_port)],
                input=log_line.encode('utf-8'),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False

    def read_tracker_file(self, file_path: Path, default: int = 0) -> int:
        """Read position or inode from tracker file (safe)"""
        try:
            if file_path.exists():
                content = file_path.read_text().strip()
                return int(content) if content else default
        except (ValueError, IOError):
            pass
        return default

    def write_tracker_file(self, file_path: Path, value: int):
        """Write position or inode to tracker file (safe)"""
        try:
            file_path.write_text(str(value))
        except IOError:
            pass  # Fail silently

    def reset_all_positions(self):
        """Reset all position tracking files"""
        self.log_reset("=" * 60)
        self.log_reset("MIDNIGHT AUTO-RESET TRIGGERED")
        self.log_reset("=" * 60)
        self.log_reset("Resetting all position trackers and inodes...")

        if self.position_dir.exists():
            removed_count = 0
            for file in self.position_dir.glob('*'):
                try:
                    file.unlink()
                    self.log_reset(f"  Removed: {file.name}")
                    removed_count += 1
                except OSError as e:
                    self.log_error(f"  Failed to remove {file.name}: {e}")

            if removed_count > 0:
                self.log_reset(f"Successfully reset {removed_count} tracker file(s)")
            else:
                self.log_warn("No tracker files found to reset")
        else:
            self.log_warn(f"Position directory does not exist: {self.position_dir}")

        self.log_reset("All monitored files will start from the beginning")
        self.log_reset("=" * 60)

        # Update the last reset date
        self.last_reset_date = datetime.now().date()

    def check_midnight_reset(self):
        """Check if it's past midnight and reset if needed"""
        current_date = datetime.now().date()

        # If the date has changed since last reset, trigger reset
        if current_date > self.last_reset_date:
            self.reset_all_positions()

    def process_line(self, line: str, file_path: str) -> Optional[str]:
        """
        Process a line - decrypt if needed, otherwise return as-is

        Args:
            line: Raw line from file
            file_path: Path to the file being monitored

        Returns:
            Processed line or None if processing fails
        """
        # Check if this file needs decryption
        if file_path in self.encrypted_files:
            decrypted = self.decryptor.decrypt_line(line)
            if decrypted:
                return decrypted
            else:
                # Decryption failed - skip this line
                return None
        else:
            # Not encrypted, return as-is
            return line

    def monitor_file(self, file_path: str, position_file: Path,
                    inode_file: Path, file_label: str):
        """Monitor a single file for new content (graceful handling)"""
        # Check if file exists - if not, warn once and skip
        if not os.path.exists(file_path):
            if file_path not in self.warned_files:
                self.log_warn(f"File not found: {file_path} (skipping, will retry later)")
                self.warned_files[file_path] = True
            return

        # Clear warning flag if file now exists
        if file_path in self.warned_files:
            self.log_info(f"File now available: {file_path}")
            del self.warned_files[file_path]

        # Get current file stats
        try:
            stat_info = os.stat(file_path)
            current_size = stat_info.st_size
            current_inode = stat_info.st_ino
        except (OSError, FileNotFoundError):
            return

        # If file is empty and has zero size, skip
        if current_size == 0:
            return

        # Read last position and inode
        last_position = self.read_tracker_file(position_file, 0)
        last_inode = self.read_tracker_file(inode_file, 0)

        # Check for file rotation (inode changed)
        if current_inode != last_inode and last_inode != 0:
            self.log_warn(
                f"File {file_label} was ROTATED "
                f"(inode changed: {last_inode} -> {current_inode})"
            )
            self.log_msg("Starting fresh from beginning of new file")
            last_position = 0
            self.write_tracker_file(inode_file, current_inode)

        # Check if file was truncated (same inode, but smaller size)
        if current_size < last_position and current_inode == last_inode:
            self.log_warn(
                f"File {file_label} was truncated (same inode), resetting position"
            )
            last_position = 0

        # Read new lines
        if current_size > last_position:
            try:
                with open(file_path, 'rb') as f:
                    # Seek to last position
                    f.seek(last_position)
                    # Read new content
                    new_content = f.read(current_size - last_position)

                # Decode and process lines
                try:
                    text_content = new_content.decode('utf-8')
                except UnicodeDecodeError:
                    text_content = new_content.decode('utf-8', errors='ignore')

                for line in text_content.splitlines():
                    # Skip empty lines
                    if not line.strip():
                        continue

                    # Process line (decrypt if needed)
                    processed_line = self.process_line(line, file_path)

                    if processed_line:
                        # Send to remote destination
                        self.send_log_udp(processed_line)

                        # Print locally
                        print(processed_line)

                # Update position and inode (safe write)
                self.write_tracker_file(position_file, current_size)
                self.write_tracker_file(inode_file, current_inode)

            except IOError:
                pass  # Fail silently, will retry next iteration
        else:
            # Even if no new content, update inode if it changed
            if current_inode != last_inode:
                self.write_tracker_file(inode_file, current_inode)

    def monitor_date_based_file(self, directory: str, prefix: str,
                               position_file: Path, inode_file: Path,
                               current_file_tracker: Path, file_label: str):
        """Monitor date-based file that automatically switches daily (graceful handling)"""
        # Check if directory exists - if not, warn once and skip
        if not os.path.isdir(directory):
            if directory not in self.warned_files:
                self.log_warn(f"Directory not found: {directory} (skipping date-based monitoring)")
                self.warned_files[directory] = True
            return

        # Clear warning flag if directory now exists
        if directory in self.warned_files:
            self.log_info(f"Directory now available: {directory}")
            del self.warned_files[directory]

        # Get today's expected filename
        todays_file = self.get_todays_file(directory, prefix)

        # Read the last monitored file path
        last_monitored_file = ""
        if current_file_tracker.exists():
            try:
                last_monitored_file = current_file_tracker.read_text().strip()
            except IOError:
                pass

        # Check if we need to switch to a new file
        if todays_file != last_monitored_file:
            if os.path.exists(todays_file):
                self.log_info(f"DATE-BASED FILE SWITCH DETECTED for {file_label}")
                self.log_info(f"  Old file: {last_monitored_file or 'NONE'}")
                self.log_info(f"  New file: {todays_file}")

                # Reset position and inode for the new file
                self.write_tracker_file(position_file, 0)
                self.write_tracker_file(inode_file, 0)
                try:
                    current_file_tracker.write_text(todays_file)
                except IOError:
                    pass

                self.log_msg(f"Starting to monitor new date-based file: {todays_file}")

                # Clear any warning for this file
                if todays_file in self.warned_files:
                    del self.warned_files[todays_file]
            else:
                # Today's file doesn't exist yet - warn once
                if todays_file not in self.warned_files:
                    self.log_warn(f"Date-based file not found: {todays_file} (will retry)")
                    self.warned_files[todays_file] = True
                return

        # Monitor the current file (today's file)
        if os.path.exists(todays_file):
            self.monitor_file(todays_file, position_file, inode_file, file_label)

    def run(self):
        """Main monitoring loop"""
        # Position files for tracking
        position_files = {
            'file1': self.position_dir / 'file1.pos',
            'file2': self.position_dir / 'file2.pos',
            'file3': self.position_dir / 'file3.pos',
            'file4': self.position_dir / 'file4.pos',
            'date_based': self.position_dir / 'date_based.pos',
        }

        # Inode files for rotation detection
        inode_files = {
            'file1': self.position_dir / 'file1.inode',
            'file2': self.position_dir / 'file2.inode',
            'file3': self.position_dir / 'file3.inode',
            'file4': self.position_dir / 'file4.inode',
            'date_based': self.position_dir / 'date_based.inode',
        }

        # Current file tracker for date-based file
        current_file_tracker = self.position_dir / 'date_based.current'

        self.log_msg("Monitoring started (with decryption support)...")
        self.log_msg("Midnight auto-reset: ENABLED (resets at 12:00 AM daily)")

        while self.running:
            try:
                # Check for midnight reset before monitoring
                self.check_midnight_reset()

                # Monitor static files with inode tracking (graceful)
                file1_label = "File1" + (" [ENCRYPTED]" if self.file1 in self.encrypted_files else "")
                file2_label = "File2" + (" [ENCRYPTED]" if self.file2 in self.encrypted_files else "")
                file3_label = "File3" + (" [ENCRYPTED]" if self.file3 in self.encrypted_files else "")
                file4_label = "File4" + (" [ENCRYPTED]" if self.file4 in self.encrypted_files else "")

                self.monitor_file(
                    self.file1, position_files['file1'],
                    inode_files['file1'], file1_label
                )
                self.monitor_file(
                    self.file2, position_files['file2'],
                    inode_files['file2'], file2_label
                )
                self.monitor_file(
                    self.file3, position_files['file3'],
                    inode_files['file3'], file3_label
                )
                self.monitor_file(
                    self.file4, position_files['file4'],
                    inode_files['file4'], file4_label
                )

                # Monitor date-based file (auto-switches to today's file, graceful)
                self.monitor_date_based_file(
                    self.date_based_dir, self.date_based_prefix,
                    position_files['date_based'],
                    inode_files['date_based'],
                    current_file_tracker,
                    "Date-Based-File"
                )

                # Sleep for a short interval
                time.sleep(1)

            except Exception as e:
                # Catch any unexpected errors and continue
                self.log_error(f"Unexpected error in monitoring loop: {e}")
                time.sleep(1)


def get_user_input(prompt: str, default: str) -> str:
    """Get user input with a default value"""
    user_input = input(f"{prompt} [{Colors.BLUE}{default}{Colors.NC}]: ").strip()
    return user_input if user_input else default


def get_yes_no(prompt: str, default: str = "y") -> bool:
    """Get yes/no input from user"""
    response = get_user_input(f"{prompt} (y/n)", default).lower()
    return response == 'y'


def interactive_config() -> dict:
    """Interactive configuration mode"""
    print(f"\n{Colors.GREEN}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}Interactive Configuration Mode{Colors.NC}")
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")
    print("Press Enter to use default values shown in [blue]\n")

    config = {}

    # Ask which monitoring mode to enable
    print(f"{Colors.YELLOW}Monitoring Mode Selection:{Colors.NC}")
    config['enable_log_monitor'] = get_yes_no("Enable Log Forwarding Monitor?", "y")
    config['enable_sap_wazuh'] = get_yes_no("Enable SAP-to-Wazuh Monitor?", "y")
    print()

    if not config['enable_log_monitor'] and not config['enable_sap_wazuh']:
        print(f"{Colors.RED}Error: At least one monitoring mode must be enabled!{Colors.NC}")
        sys.exit(1)

    # Log Monitor Configuration
    if config['enable_log_monitor']:
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
        print(f"{Colors.CYAN}LOG FORWARDING MONITOR CONFIGURATION{Colors.NC}")
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}\n")

        # Network configuration
        print(f"{Colors.YELLOW}Network Configuration:{Colors.NC}")
        config['ip'] = get_user_input("Destination IP", DEFAULT_IP)
        config['port'] = int(get_user_input("Destination Port", str(DEFAULT_PORT)))
        print()

        # File paths
        print(f"{Colors.YELLOW}File Paths to Monitor:{Colors.NC}")
        config['file1'] = get_user_input("File 1 (dev_icm)", DEFAULT_FILE1)
        config['file2'] = get_user_input("File 2 (system_logs.json)", DEFAULT_FILE2)
        config['file3'] = get_user_input("File 3 (sal_export.json)", DEFAULT_FILE3)
        config['file4'] = get_user_input("File 4 (sap_version.json)", DEFAULT_FILE4)
        print()

        # Date-based file configuration
        print(f"{Colors.YELLOW}Date-Based File Configuration:{Colors.NC}")
        config['date_based_dir'] = get_user_input("Date-based directory", DEFAULT_DATE_BASED_DIR)
        config['date_based_prefix'] = get_user_input("Date-based filename prefix", DEFAULT_DATE_BASED_PREFIX)
        print()

        # Position directory
        print(f"{Colors.YELLOW}Position Tracking:{Colors.NC}")
        config['position_dir'] = get_user_input("Position directory", DEFAULT_POSITION_DIR)
        print()

        # Encrypted files
        print(f"{Colors.YELLOW}Encrypted Files Configuration:{Colors.NC}")
        print("Mark which files are encrypted (will be auto-decrypted)")

        encrypted = set()
        if get_yes_no(f"Is File 2 ({config['file2']}) encrypted?", "y"):
            encrypted.add(config['file2'])
        if get_yes_no(f"Is File 3 ({config['file3']}) encrypted?", "y"):
            encrypted.add(config['file3'])
        if get_yes_no(f"Is File 4 ({config['file4']}) encrypted?", "y"):
            encrypted.add(config['file4'])

        config['encrypted_files'] = encrypted
        print()

    # SAP-to-Wazuh Monitor Configuration
    if config['enable_sap_wazuh']:
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
        print(f"{Colors.CYAN}SAP-TO-WAZUH MONITOR CONFIGURATION{Colors.NC}")
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}\n")

        # Input file configuration
        print(f"{Colors.YELLOW}Input File Configuration:{Colors.NC}")
        config['sap_input_file'] = get_user_input("SAP Input File", DEFAULT_SAP_INPUT_FILE)
        config['sap_local_out'] = get_user_input("Local Output File", DEFAULT_SAP_LOCAL_OUT)
        config['sap_local_temp'] = get_user_input("Local Temp File", DEFAULT_SAP_LOCAL_TEMP)
        config['sap_hash_file'] = get_user_input("Hash Tracking File", DEFAULT_SAP_HASH_FILE)
        config['sap_log_file'] = get_user_input("Log File", DEFAULT_SAP_LOG_FILE)
        print()

        # Wazuh server configuration
        print(f"{Colors.YELLOW}Wazuh Server Configuration:{Colors.NC}")
        config['wazuh_user'] = get_user_input("Wazuh Username", DEFAULT_WAZUH_USER)
        config['wazuh_host'] = get_user_input("Wazuh Host/IP", DEFAULT_WAZUH_HOST)
        config['wazuh_port'] = int(get_user_input("Wazuh SSH Port", str(DEFAULT_WAZUH_PORT)))
        config['wazuh_pass'] = get_user_input("Wazuh Password", DEFAULT_WAZUH_PASS)
        config['wazuh_sap_dir'] = get_user_input("Wazuh SAP Directory", DEFAULT_WAZUH_SAP_DIR)
        config['wazuh_temp_dir'] = get_user_input("Wazuh Temp Directory", DEFAULT_WAZUH_TEMP_DIR)
        print()

        # Monitoring settings
        print(f"{Colors.YELLOW}Monitoring Settings:{Colors.NC}")
        config['check_interval'] = int(get_user_input("Check Interval (seconds)", str(DEFAULT_CHECK_INTERVAL)))
        config['stable_wait'] = int(get_user_input("Stability Wait (seconds)", str(DEFAULT_STABLE_WAIT)))
        print()

        # Skip keywords configuration
        print(f"{Colors.YELLOW}Skip Keywords Configuration:{Colors.NC}")
        if get_yes_no("Use default skip keywords?", "y"):
            config['skip_keywords'] = DEFAULT_SKIP_KEYWORDS
        else:
            print("Enter keywords to skip (comma-separated):")
            keywords_input = input("> ").strip()
            if keywords_input:
                config['skip_keywords'] = [k.strip() for k in keywords_input.split(',')]
            else:
                config['skip_keywords'] = []
        print()

    print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")

    return config


def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def reset_file_tracking(position_dir: str, file_id: str):
    """Reset tracking for a specific file"""
    position_path = Path(position_dir)

    if not position_path.exists():
        LogMonitor.log_error(f"Position directory does not exist: {position_dir}")
        return False

    # Map file identifiers to tracker files
    file_map = {
        'file1': ['file1.pos', 'file1.inode'],
        'file2': ['file2.pos', 'file2.inode'],
        'file3': ['file3.pos', 'file3.inode'],
        'file4': ['file4.pos', 'file4.inode'],
        'date': ['date_based.pos', 'date_based.inode', 'date_based.current'],
    }

    if file_id not in file_map:
        LogMonitor.log_error(f"Invalid file identifier: {file_id}")
        LogMonitor.log_error("Valid options: file1, file2, file3, file4, date")
        return False

    LogMonitor.log_msg(f"Resetting tracking for: {file_id}")

    removed_count = 0
    for tracker_file in file_map[file_id]:
        tracker_path = position_path / tracker_file
        if tracker_path.exists():
            try:
                tracker_path.unlink()
                LogMonitor.log_info(f"  Removed: {tracker_file}")
                removed_count += 1
            except OSError as e:
                LogMonitor.log_error(f"  Failed to remove {tracker_file}: {e}")
        else:
            LogMonitor.log_info(f"  Not found: {tracker_file} (skipping)")

    if removed_count > 0:
        LogMonitor.log_msg(f"Successfully reset {removed_count} tracker file(s) for {file_id}")
        LogMonitor.log_msg("The file will be monitored from the beginning on next run")
    else:
        LogMonitor.log_warn(f"No tracker files found for {file_id}")

    return True


def run_monitors(log_monitor: Optional[LogMonitor], sap_wazuh: Optional[SAPWazuhMonitor]):
    """Run both monitors concurrently using threads"""
    threads = []

    if log_monitor:
        log_thread = threading.Thread(target=log_monitor.run, daemon=True)
        log_thread.start()
        threads.append(log_thread)

    if sap_wazuh:
        sap_thread = threading.Thread(target=sap_wazuh.run, daemon=True)
        sap_thread.start()
        threads.append(sap_thread)

    # Wait for threads (they run indefinitely)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Shutting down monitors...{Colors.NC}")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Log Monitor with Log Forwarding and SAP-to-Wazuh Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  # Interactive mode (default - prompts for all settings)
  %(prog)s

  # Non-interactive mode - Log Monitor only
  %(prog)s --non-interactive --log-monitor -i 10.0.0.100 -p 514

  # Non-interactive mode - SAP-to-Wazuh only
  %(prog)s --non-interactive --sap-wazuh --sap-input /tmp/sap.xml --wazuh-host 192.168.1.100

  # Non-interactive mode - Both monitors
  %(prog)s --non-interactive --log-monitor --sap-wazuh -i 10.0.0.100 --wazuh-host 192.168.1.100

  # Reset tracking for a specific file
  %(prog)s --reset-file file2

NOTE: Position tracking automatically resets at midnight (12:00 AM) daily for log monitor.
'''
    )

    parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Non-interactive mode (use command-line arguments only)'
    )

    # Monitor selection
    parser.add_argument(
        '--log-monitor',
        action='store_true',
        help='Enable Log Forwarding Monitor'
    )
    parser.add_argument(
        '--sap-wazuh',
        action='store_true',
        help='Enable SAP-to-Wazuh Monitor'
    )

    # Log Monitor arguments
    parser.add_argument(
        '-i', '--ip',
        default=DEFAULT_IP,
        help=f'Destination IP address (default: {DEFAULT_IP})'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Destination port (default: {DEFAULT_PORT})'
    )
    parser.add_argument(
        '--file1',
        default=DEFAULT_FILE1,
        help=f'File 1 path (default: {DEFAULT_FILE1})'
    )
    parser.add_argument(
        '--file2',
        default=DEFAULT_FILE2,
        help=f'File 2 path (default: {DEFAULT_FILE2})'
    )
    parser.add_argument(
        '--file3',
        default=DEFAULT_FILE3,
        help=f'File 3 path (default: {DEFAULT_FILE3})'
    )
    parser.add_argument(
        '--file4',
        default=DEFAULT_FILE4,
        help=f'File 4 path (default: {DEFAULT_FILE4})'
    )
    parser.add_argument(
        '--date-dir',
        default=DEFAULT_DATE_BASED_DIR,
        help=f'Date-based file directory (default: {DEFAULT_DATE_BASED_DIR})'
    )
    parser.add_argument(
        '--date-prefix',
        default=DEFAULT_DATE_BASED_PREFIX,
        help=f'Date-based filename prefix (default: {DEFAULT_DATE_BASED_PREFIX})'
    )
    parser.add_argument(
        '--position-dir',
        default=DEFAULT_POSITION_DIR,
        help=f'Position tracking directory (default: {DEFAULT_POSITION_DIR})'
    )
    parser.add_argument(
        '--no-encrypt-file2',
        action='store_true',
        help='File 2 is NOT encrypted (default: encrypted)'
    )
    parser.add_argument(
        '--no-encrypt-file3',
        action='store_true',
        help='File 3 is NOT encrypted (default: encrypted)'
    )
    parser.add_argument(
        '--no-encrypt-file4',
        action='store_true',
        help='File 4 is NOT encrypted (default: encrypted)'
    )

    # SAP-to-Wazuh arguments
    parser.add_argument(
        '--sap-input',
        default=DEFAULT_SAP_INPUT_FILE,
        help=f'SAP input file (default: {DEFAULT_SAP_INPUT_FILE})'
    )
    parser.add_argument(
        '--sap-output',
        default=DEFAULT_SAP_LOCAL_OUT,
        help=f'Local output file (default: {DEFAULT_SAP_LOCAL_OUT})'
    )
    parser.add_argument(
        '--sap-temp',
        default=DEFAULT_SAP_LOCAL_TEMP,
        help=f'Local temp file (default: {DEFAULT_SAP_LOCAL_TEMP})'
    )
    parser.add_argument(
        '--sap-hash',
        default=DEFAULT_SAP_HASH_FILE,
        help=f'Hash file (default: {DEFAULT_SAP_HASH_FILE})'
    )
    parser.add_argument(
        '--sap-log',
        default=DEFAULT_SAP_LOG_FILE,
        help=f'SAP log file (default: {DEFAULT_SAP_LOG_FILE})'
    )
    parser.add_argument(
        '--wazuh-user',
        default=DEFAULT_WAZUH_USER,
        help=f'Wazuh username (default: {DEFAULT_WAZUH_USER})'
    )
    parser.add_argument(
        '--wazuh-host',
        default=DEFAULT_WAZUH_HOST,
        help=f'Wazuh host/IP (default: {DEFAULT_WAZUH_HOST})'
    )
    parser.add_argument(
        '--wazuh-port',
        type=int,
        default=DEFAULT_WAZUH_PORT,
        help=f'Wazuh SSH port (default: {DEFAULT_WAZUH_PORT})'
    )
    parser.add_argument(
        '--wazuh-pass',
        default=DEFAULT_WAZUH_PASS,
        help=f'Wazuh password (default: {DEFAULT_WAZUH_PASS})'
    )
    parser.add_argument(
        '--wazuh-sap-dir',
        default=DEFAULT_WAZUH_SAP_DIR,
        help=f'Wazuh SAP directory (default: {DEFAULT_WAZUH_SAP_DIR})'
    )
    parser.add_argument(
        '--wazuh-temp-dir',
        default=DEFAULT_WAZUH_TEMP_DIR,
        help=f'Wazuh temp directory (default: {DEFAULT_WAZUH_TEMP_DIR})'
    )
    parser.add_argument(
        '--check-interval',
        type=int,
        default=DEFAULT_CHECK_INTERVAL,
        help=f'Check interval in seconds (default: {DEFAULT_CHECK_INTERVAL})'
    )
    parser.add_argument(
        '--stable-wait',
        type=int,
        default=DEFAULT_STABLE_WAIT,
        help=f'Stability wait in seconds (default: {DEFAULT_STABLE_WAIT})'
    )

    # Reset options
    parser.add_argument(
        '-r', '--reset',
        action='store_true',
        help='Reset ALL position trackers (use --reset-file for selective reset)'
    )
    parser.add_argument(
        '--reset-file',
        choices=['file1', 'file2', 'file3', 'file4', 'date'],
        help='Reset tracking for a specific file only (file1, file2, file3, file4, or date)'
    )

    args = parser.parse_args()

    # Handle selective file reset
    if args.reset_file:
        position_dir = args.position_dir
        success = reset_file_tracking(position_dir, args.reset_file)
        sys.exit(0 if success else 1)

    # Default to interactive mode unless --non-interactive is specified
    if not args.non_interactive:
        config = interactive_config()
        
        enable_log_monitor = config['enable_log_monitor']
        enable_sap_wazuh = config['enable_sap_wazuh']

        # Log Monitor config
        if enable_log_monitor:
            ip = config['ip']
            port = config['port']
            file1 = config['file1']
            file2 = config['file2']
            file3 = config['file3']
            file4 = config['file4']
            date_based_dir = config['date_based_dir']
            date_based_prefix = config['date_based_prefix']
            position_dir = config['position_dir']
            encrypted_files = config['encrypted_files']
            reset = False

        # SAP-Wazuh config
        if enable_sap_wazuh:
            sap_input_file = config['sap_input_file']
            sap_local_out = config['sap_local_out']
            sap_local_temp = config['sap_local_temp']
            sap_hash_file = config['sap_hash_file']
            sap_log_file = config['sap_log_file']
            wazuh_user = config['wazuh_user']
            wazuh_host = config['wazuh_host']
            wazuh_port = config['wazuh_port']
            wazuh_pass = config['wazuh_pass']
            wazuh_sap_dir = config['wazuh_sap_dir']
            wazuh_temp_dir = config['wazuh_temp_dir']
            check_interval = config['check_interval']
            stable_wait = config['stable_wait']
            skip_keywords = config['skip_keywords']

    else:
        # Non-interactive mode
        enable_log_monitor = args.log_monitor
        enable_sap_wazuh = args.sap_wazuh

        # If neither is specified, enable both by default
        if not enable_log_monitor and not enable_sap_wazuh:
            enable_log_monitor = True
            enable_sap_wazuh = True

        # Log Monitor config
        ip = args.ip
        port = args.port
        file1 = args.file1
        file2 = args.file2
        file3 = args.file3
        file4 = args.file4
        date_based_dir = args.date_dir
        date_based_prefix = args.date_prefix
        position_dir = args.position_dir
        reset = args.reset

        # Encrypted files
        encrypted_files = set()
        if not args.no_encrypt_file2:
            encrypted_files.add(file2)
        if not args.no_encrypt_file3:
            encrypted_files.add(file3)
        if not args.no_encrypt_file4:
            encrypted_files.add(file4)

        # SAP-Wazuh config
        sap_input_file = args.sap_input
        sap_local_out = args.sap_output
        sap_local_temp = args.sap_temp
        sap_hash_file = args.sap_hash
        sap_log_file = args.sap_log
        wazuh_user = args.wazuh_user
        wazuh_host = args.wazuh_host
        wazuh_port = args.wazuh_port
        wazuh_pass = args.wazuh_pass
        wazuh_sap_dir = args.wazuh_sap_dir
        wazuh_temp_dir = args.wazuh_temp_dir
        check_interval = args.check_interval
        stable_wait = args.stable_wait
        skip_keywords = DEFAULT_SKIP_KEYWORDS

    # Validate configurations
    if enable_log_monitor:
        if not validate_ip(ip):
            LogMonitor.log_error(f"Invalid IP address: {ip}")
            sys.exit(1)

        if not (1 <= port <= 65535):
            LogMonitor.log_error(f"Invalid port number: {port} (must be 1-65535)")
            sys.exit(1)

        # If requested, reset ALL position trackers
        if reset:
            LogMonitor.log_msg("Resetting ALL position trackers and inodes")
            position_path = Path(position_dir)
            if position_path.exists():
                for file in position_path.glob('*'):
                    try:
                        file.unlink()
                        LogMonitor.log_info(f"  Removed: {file.name}")
                    except OSError:
                        pass

    # Display configuration
    print(f"\n{Colors.GREEN}{'='*70}{Colors.NC}")
    print(f"{Colors.GREEN}Enhanced Log Monitor Starting{Colors.NC}")
    print(f"{Colors.GREEN}{'='*70}{Colors.NC}\n")

    # Initialize monitors
    log_monitor_instance = None
    sap_wazuh_instance = None

    if enable_log_monitor:
        print(f"{Colors.CYAN}LOG FORWARDING MONITOR: ENABLED{Colors.NC}")
        print(f"  Destination: {ip}:{port}")
        print(f"  Protocol: UDP (raw)")
        print(f"  Decryption: ENABLED (automatic)")
        print(f"  File Rotation Detection: ENABLED (inode tracking)")
        print(f"  Date-Based File Monitoring: ENABLED")
        print(f"  Midnight Auto-Reset: ENABLED (resets at 12:00 AM daily)")
        print(f"  Monitoring files:")
        enc_label1 = " [ENCRYPTED]" if file1 in encrypted_files else ""
        enc_label2 = " [ENCRYPTED]" if file2 in encrypted_files else ""
        enc_label3 = " [ENCRYPTED]" if file3 in encrypted_files else ""
        enc_label4 = " [ENCRYPTED]" if file4 in encrypted_files else ""
        print(f"    1. {file1}{enc_label1}")
        print(f"    2. {file2}{enc_label2}")
        print(f"    3. {file3}{enc_label3}")
        print(f"    4. {file4}{enc_label4}")
        print(f"    5. {date_based_dir}/{date_based_prefix}YYYYMMDD (auto-switching)")
        print(f"  Position tracking: {position_dir}")
        print()

        log_monitor_instance = LogMonitor(
            ip, port, position_dir, file1, file2, file3, file4,
            date_based_dir, date_based_prefix, encrypted_files
        )

    if enable_sap_wazuh:
        print(f"{Colors.CYAN}SAP-TO-WAZUH MONITOR: ENABLED{Colors.NC}")
        print(f"  Input file: {sap_input_file}")
        print(f"  Wazuh server: {wazuh_user}@{wazuh_host}:{wazuh_port}")
        print(f"  Destination: {wazuh_sap_dir}/sap_sca_results.txt")
        print(f"  Check interval: {check_interval}s")
        print(f"  Stability wait: {stable_wait}s")
        print(f"  Skip keywords: {len(skip_keywords)} configured")
        print(f"  Log file: {sap_log_file}")
        print()

        sap_wazuh_instance = SAPWazuhMonitor(
            sap_input_file, sap_local_out, sap_local_temp, sap_hash_file,
            sap_log_file, wazuh_user, wazuh_host, wazuh_port,
            wazuh_sap_dir, wazuh_temp_dir, wazuh_pass, check_interval,
            stable_wait, skip_keywords
        )

    print(f"{Colors.GREEN}{'='*70}{Colors.NC}")
    print(f"{Colors.YELLOW}Press Ctrl+C to stop all monitors{Colors.NC}")
    print(f"{Colors.GREEN}{'='*70}{Colors.NC}\n")

    # Run monitors
    run_monitors(log_monitor_instance, sap_wazuh_instance)


if __name__ == "__main__":
    main()