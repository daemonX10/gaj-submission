import os
import subprocess
import time
import json
import logging
import tempfile
import hashlib
import platform
import psutil
import threading
from queue import Queue
import re
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='dynamic_analysis.log'
)
logger = logging.getLogger('DynamicAnalysis')

class DynamicAnalyzer:
    """
    Performs dynamic analysis of potentially malicious files in a controlled environment.
    Note: This is a simplified version that uses process isolation.
    For production use, a proper sandbox solution should be implemented.
    """
    def __init__(self, timeout=60, max_memory_mb=500):
        """
        Initialize the dynamic analyzer
        
        Args:
            timeout: Maximum time to run the sample (seconds)
            max_memory_mb: Maximum memory allowed for the process (MB)
        """
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.is_windows = platform.system().lower() == 'windows'
        self.temp_dir = tempfile.mkdtemp(prefix="dynamic_analysis_")
        logger.info(f"Created temporary directory: {self.temp_dir}")
        
        # Initialize results storage
        self.monitor_queue = Queue()
        self.results = {}
        
    def analyze_file(self, file_path):
        """
        Analyze a file by executing it in a controlled environment
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
        
        # Calculate file hash
        file_hash = self._calculate_hash(file_path)
        
        # Store initial process state
        initial_processes = self._get_running_processes()
        initial_files = self._get_directory_state()
        
        # Execute the file with monitoring
        execution_info = self._execute_sample(file_path)
        
        # Get post-execution state
        time.sleep(2)  # Wait for any delayed actions
        final_processes = self._get_running_processes()
        final_files = self._get_directory_state()
        
        # Analyze differences
        created_processes = self._compare_processes(initial_processes, final_processes)
        file_changes = self._compare_files(initial_files, final_files)
        
        # Get network connections
        network_activity = self._get_network_activity(execution_info.get('pid'))
        
        # Compile behavioral indicators
        behavioral_indicators = self._analyze_behavior(execution_info, created_processes, 
                                                     file_changes, network_activity)
        
        # Compile results
        results = {
            "file_hash": file_hash,
            "file_path": file_path,
            "execution_info": execution_info,
            "created_processes": created_processes,
            "file_changes": file_changes,
            "network_activity": network_activity,
            "behavioral_indicators": behavioral_indicators,
            "malware_type_indicators": self._determine_malware_type(behavioral_indicators),
            "risk_score": self._calculate_risk_score(behavioral_indicators),
        }
        
        # Clean up
        self._cleanup()
        
        return results
    
    def _execute_sample(self, file_path):
        """Execute the sample and monitor its behavior"""
        logger.info(f"Executing file: {file_path}")
        
        execution_info = {
            "executed": False,
            "execution_time": 0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "terminated": False,
            "pid": None,
            "children": []
        }
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._process_monitor_thread)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        start_time = time.time()
        
        try:
            # Prepare command based on file type
            file_extension = os.path.splitext(file_path)[1].lower()
            
            if file_extension == '.exe' or file_extension == '.dll':
                if self.is_windows:
                    command = [file_path]
                else:
                    # Cannot directly execute Windows executables on non-Windows
                    logger.warning("Cannot execute Windows executables on non-Windows platform")
                    return {"error": "Platform incompatibility"}
                    
            elif file_extension == '.ps1':
                if self.is_windows:
                    command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", file_path]
                else:
                    logger.warning("Cannot execute PowerShell scripts on non-Windows platform")
                    return {"error": "Platform incompatibility"}
                    
            elif file_extension == '.bat' or file_extension == '.cmd':
                if self.is_windows:
                    command = ["cmd.exe", "/c", file_path]
                else:
                    logger.warning("Cannot execute batch files on non-Windows platform")
                    return {"error": "Platform incompatibility"}
                    
            elif file_extension == '.js':
                if self.is_windows:
                    command = ["cscript.exe", "//nologo", file_path]
                else:
                    command = ["node", file_path]
                    
            elif file_extension == '.vbs':
                if self.is_windows:
                    command = ["cscript.exe", "//nologo", file_path]
                else:
                    logger.warning("Cannot execute VBScript on non-Windows platform")
                    return {"error": "Platform incompatibility"}
                    
            else:
                logger.warning(f"Unsupported file type: {file_extension}")
                return {"error": f"Unsupported file type: {file_extension}"}
            
            # Execute the command with timeout
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.temp_dir,
                shell=False
            )
            
            execution_info["executed"] = True
            execution_info["pid"] = process.pid
            
            # Add to monitoring queue
            self.monitor_queue.put(process.pid)
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                execution_info["stdout"] = stdout.decode('utf-8', errors='ignore')
                execution_info["stderr"] = stderr.decode('utf-8', errors='ignore')
                execution_info["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"Process timed out after {self.timeout} seconds, terminating")
                process.kill()
                execution_info["terminated"] = True
                execution_info["exit_code"] = -1
                
        except Exception as e:
            logger.error(f"Error executing file: {e}")
            execution_info["error"] = str(e)
            
        execution_info["execution_time"] = time.time() - start_time
        
        return execution_info
    
    def _process_monitor_thread(self):
        """Monitor processes for resource usage and child processes"""
        monitored_pids = set()
        pid_to_children = {}
        
        while True:
            try:
                # Get new PIDs from queue
                while not self.monitor_queue.empty():
                    new_pid = self.monitor_queue.get()
                    monitored_pids.add(new_pid)
                    pid_to_children[new_pid] = []
                
                if not monitored_pids:
                    time.sleep(0.1)
                    continue
                
                # Check each monitored process
                for pid in list(monitored_pids):
                    try:
                        if not psutil.pid_exists(pid):
                            monitored_pids.remove(pid)
                            continue
                            
                        process = psutil.Process(pid)
                        
                        # Check resource usage
                        memory_info = process.memory_info()
                        memory_mb = memory_info.rss / (1024 * 1024)
                        
                        if memory_mb > self.max_memory_mb:
                            logger.warning(f"Process {pid} exceeded memory limit, terminating")
                            process.kill()
                            monitored_pids.remove(pid)
                            continue
                        
                        # Check for child processes
                        try:
                            children = process.children(recursive=False)
                            for child in children:
                                child_pid = child.pid
                                if child_pid not in monitored_pids:
                                    logger.info(f"Monitoring new child process: {child_pid}")
                                    monitored_pids.add(child_pid)
                                    self.monitor_queue.put(child_pid)
                                    pid_to_children[pid].append(child_pid)
                        except psutil.NoSuchProcess:
                            pass
                            
                    except psutil.NoSuchProcess:
                        monitored_pids.remove(pid)
                        continue
                    except Exception as e:
                        logger.error(f"Error monitoring process {pid}: {e}")
                
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error in process monitor thread: {e}")
                time.sleep(1)
    
    def _get_running_processes(self):
        """Get a list of all running processes"""
        processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                process_info = proc.info
                pid = process_info['pid']
                processes[pid] = {
                    'name': process_info.get('name', ''),
                    'exe': process_info.get('exe', ''),
                    'cmdline': process_info.get('cmdline', [])
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return processes
    
    def _get_directory_state(self):
        """Get the state of files in important directories"""
        files = {}
        
        # Check key directories
        directories = [
            self.temp_dir,
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', '')
        ]
        
        for directory in directories:
            if not directory or not os.path.exists(directory):
                continue
                
            for root, _, filenames in os.walk(directory):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        stat = os.stat(file_path)
                        files[file_path] = {
                            'size': stat.st_size,
                            'modified': stat.st_mtime
                        }
                    except OSError:
                        pass
                        
        return files
    
    def _compare_processes(self, before, after):
        """Compare process lists to find new processes"""
        new_processes = []
        
        for pid, info in after.items():
            if pid not in before:
                new_processes.append({
                    'pid': pid,
                    'name': info.get('name', ''),
                    'exe': info.get('exe', ''),
                    'cmdline': info.get('cmdline', [])
                })
                
        return new_processes
    
    def _compare_files(self, before, after):
        """Compare file states to find changes"""
        changes = {
            'created': [],
            'modified': [],
            'deleted': []
        }
        
        # Find created and modified files
        for file_path, info in after.items():
            if file_path not in before:
                changes['created'].append(file_path)
            elif before[file_path]['modified'] != info['modified'] or before[file_path]['size'] != info['size']:
                changes['modified'].append(file_path)
        
        # Find deleted files
        for file_path in before:
            if file_path not in after:
                changes['deleted'].append(file_path)
                
        return changes
    
    def _get_network_activity(self, pid):
        """Get network connections for a process and its children"""
        if not pid:
            return []
            
        connections = []
        
        try:
            if not psutil.pid_exists(pid):
                return connections
                
            process = psutil.Process(pid)
            process_connections = process.connections()
            
            for conn in process_connections:
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'pid': pid,
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    })
            
            # Also check children
            try:
                for child in process.children(recursive=True):
                    child_connections = self._get_network_activity(child.pid)
                    connections.extend(child_connections)
            except psutil.NoSuchProcess:
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return connections
    
    def _analyze_behavior(self, execution_info, created_processes, file_changes, network_activity):
        """Analyze behavioral indicators of malicious activity"""
        indicators = []
        
        # Analyze process creation
        if len(created_processes) > 3:
            indicators.append("Multiple process creation")
            
        # Check for suspicious process names in created processes
        suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'schtasks', 'regedit', 'taskkill']
        for proc in created_processes:
            proc_name = proc.get('name', '').lower()
            if any(name in proc_name for name in suspicious_names):
                indicators.append(f"Created suspicious process: {proc_name}")
                
        # Check command line arguments for suspicious patterns
        for proc in created_processes:
            cmdline = ' '.join(proc.get('cmdline', [])).lower()
            if 'hidden' in cmdline or '-w hidden' in cmdline or '/hidden' in cmdline:
                indicators.append("Process launched with hidden window")
            if 'bypass' in cmdline and 'executionpolicy' in cmdline:
                indicators.append("PowerShell execution policy bypass")
            if 'downloadstring' in cmdline or 'downloadfile' in cmdline:
                indicators.append("PowerShell download command")
                
        # Analyze file activity
        if len(file_changes['created']) > 10:
            indicators.append("Created multiple files")
            
        # Check for suspicious file types
        executable_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
        for file_path in file_changes['created']:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in executable_extensions:
                indicators.append(f"Created executable file: {os.path.basename(file_path)}")
                
        # Check for autorun locations
        autorun_paths = ['startup', 'appdata\\roaming', 'programdata', 'system32']
        for file_path in file_changes['created'] + file_changes['modified']:
            lower_path = file_path.lower()
            if any(ar_path in lower_path for ar_path in autorun_paths):
                indicators.append(f"Modified autorun location: {file_path}")
                
        # Analyze network activity
        if len(network_activity) > 0:
            indicators.append("Established network connections")
            
        suspicious_ports = [4444, 8080, 443, 1337, 666]
        for conn in network_activity:
            remote = conn.get('remote_address', '')
            if remote and any(str(port) in remote for port in suspicious_ports):
                indicators.append(f"Connected to suspicious port: {remote}")
                
        # Analyze process termination
        if execution_info.get('terminated', False):
            indicators.append("Process exceeded execution timeout")
            
        # Analyze output for suspicious patterns
        combined_output = (execution_info.get('stdout', '') + execution_info.get('stderr', '')).lower()
        suspicious_outputs = ['error', 'access denied', 'permission', 'administrator', 'elevation']
        for pattern in suspicious_outputs:
            if pattern in combined_output:
                indicators.append(f"Suspicious output detected: {pattern}")
                
        return indicators
    
    def _determine_malware_type(self, behavioral_indicators):
        """Determine potential malware type based on behavioral indicators"""
        indicators_text = ' '.join(behavioral_indicators).lower()
        
        malware_types = {
            'ransomware': ['encrypt', 'bitcoin', 'ransom', 'payment', 'decrypt'],
            'trojan': ['backdoor', 'remote', 'hidden', 'stealth', 'keylog'],
            'worm': ['propagate', 'spread', 'network', 'multiple', 'replicate'],
            'spyware': ['monitor', 'spy', 'screen', 'keylog', 'surveillance'],
            'virus': ['infect', 'system file', 'corrupt', 'overwrite']
        }
        
        scores = {}
        for malware_type, patterns in malware_types.items():
            score = 0
            for pattern in patterns:
                if pattern in indicators_text:
                    score += 1
            scores[malware_type] = score
            
        # Find the highest score
        max_score = 0
        likely_type = "Unknown"
        
        for malware_type, score in scores.items():
            if score > max_score:
                max_score = score
                likely_type = malware_type
                
        return {
            'likely_type': likely_type,
            'type_scores': scores
        }
    
    def _calculate_risk_score(self, behavioral_indicators):
        """Calculate an overall risk score based on behavioral indicators"""
        if not behavioral_indicators:
            return 0
            
        # Base score is related to number of indicators
        base_score = min(len(behavioral_indicators) * 10, 70)
        
        # Additional weight for high-severity indicators
        high_severity = [
            "PowerShell execution policy bypass",
            "Process launched with hidden window",
            "Created executable file",
            "Modified autorun location",
            "Connected to suspicious port"
        ]
        
        # Count high severity indicators
        severity_points = sum(5 for indicator in behavioral_indicators 
                             if any(hs in indicator for hs in high_severity))
        
        # Calculate final score (cap at 100)
        final_score = min(base_score + severity_points, 100)
        
        # Risk level categories
        if final_score < 30:
            risk_level = "Low"
        elif final_score < 70:
            risk_level = "Medium"
        else:
            risk_level = "High"
            
        return {
            'score': final_score,
            'risk_level': risk_level
        }
    
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
                
        return sha256.hexdigest()
    
    def _cleanup(self):
        """Clean up temporary files and resources"""
        try:
            for root, dirs, files in os.walk(self.temp_dir, topdown=False):
                for file in files:
                    try:
                        os.remove(os.path.join(root, file))
                    except:
                        pass
                for dir in dirs:
                    try:
                        os.rmdir(os.path.join(root, dir))
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error cleaning up: {e}")

    def detect_evasion_techniques(self, sample_path):
        """
        Enhanced detection of evasion techniques commonly used by malware to avoid analysis
        
        Args:
            sample_path: Path to the sample file
            
        Returns:
            Dictionary with evasion techniques detected and their evidence
        """
        evasion_techniques = {
            'anti_vm': self._detect_anti_vm(sample_path),
            'anti_debug': self._detect_anti_debug(sample_path),
            'time_based_evasion': self._detect_time_based_evasion(),
            'process_injection': self._detect_process_injection(),
            'code_obfuscation': self._detect_code_obfuscation(sample_path),
            'network_evasion': self._detect_network_evasion(),
            'sandbox_detection': self._detect_sandbox_detection(),
            'memory_artifacts': self._detect_memory_artifacts()
        }
        
        return evasion_techniques
    
    def _detect_anti_vm(self, sample_path):
        """Detect anti-VM techniques used by malware"""
        evidence = []
        
        try:
            # Check for known VM detection artifacts in strings
            vm_strings = [
                'vmware', 'virtualbox', 'vbox', 'qemu', 'xen', 'parallels',
                'bochs', 'vmtools', 'vmmouse', 'vmsrvc', 'vmusrvc',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware', 
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle\\VirtualBox'
            ]
            
            # Extract strings from the sample
            with open(sample_path, 'rb') as f:
                content = f.read()
                for vm_str in vm_strings:
                    if vm_str.encode().lower() in content.lower():
                        evidence.append(f"Found VM detection string: {vm_str}")
            
            # Check for VM device queries
            vm_devices = [
                '\\Device\\VBoxGuest', 
                '\\Device\\VBoxMouse',
                '\\Device\\VMwareMouseSyncWakeupEvent'
            ]
            
            for device in vm_devices:
                if device.encode().lower() in content.lower():
                    evidence.append(f"Found VM device query: {device}")
                    
            # Check for VM-specific registry keys
            vm_registry_keys = [
                'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0',
                'HARDWARE\\Description\\System',
                'SYSTEM\\ControlSet001\\Services\\Disk\\Enum'
            ]
            
            for key in vm_registry_keys:
                if key.encode().lower() in content.lower():
                    evidence.append(f"Found VM registry key check: {key}")
                    
            # Check for CPUID feature detection (common VM detection technique)
            cpuid_markers = [b'cpuid', b'CPUID']
            for marker in cpuid_markers:
                if marker in content:
                    evidence.append("Found CPUID instruction (potential VM detection)")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error during anti-VM detection: {e}")
            
        return evidence
    
    def _detect_anti_debug(self, sample_path):
        """Detect anti-debugging techniques"""
        evidence = []
        
        try:
            # Check for known anti-debugging API calls
            debug_apis = [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                'NtQueryInformationProcess', 'FindWindow', 
                'OutputDebugString', 'GetTickCount', 'QueryPerformanceCounter',
                'ZwQueryInformationProcess', 'DebugActiveProcess'
            ]
            
            # Extract strings from the sample
            with open(sample_path, 'rb') as f:
                content = f.read()
                for api in debug_apis:
                    if api.encode() in content:
                        evidence.append(f"Found anti-debugging API: {api}")
            
            # Check for debugging flags and structures
            debug_flags = [
                'PEB!BeingDebugged', 'EFLAGS!TF', 'ProcessDebugFlags',
                'ProcessDebugPort', 'ProcessDebugObjectHandle',
                'NtGlobalFlag', 'HeapFlags'
            ]
            
            for flag in debug_flags:
                if flag.encode() in content:
                    evidence.append(f"Found debugging flag check: {flag}")
                    
        except Exception as e:
            self.logger.error(f"Error during anti-debugging detection: {e}")
            
        return evidence
    
    def _detect_time_based_evasion(self):
        """Detect time-based evasion techniques from behavioral analysis"""
        evidence = []
        
        # Check for sleep calls that might be used to evade sandbox analysis
        if hasattr(self, 'api_calls') and self.api_calls:
            sleep_apis = ['Sleep', 'NtDelayExecution', 'WaitForSingleObject', 
                         'SleepEx', 'WaitForSingleObjectEx']
            
            long_sleeps = []
            for call in self.api_calls:
                if any(api in call['api'] for api in sleep_apis):
                    # Check if sleep duration is suspiciously long (> 30 seconds)
                    if 'duration' in call and call['duration'] > 30000:
                        long_sleeps.append(f"{call['api']} with duration {call['duration']}ms")
            
            if long_sleeps:
                evidence.append(f"Found suspicious sleep calls: {', '.join(long_sleeps)}")
                
            # Look for timestamp checks
            time_apis = ['GetSystemTime', 'GetLocalTime', 'GetTickCount', 
                        'QueryPerformanceCounter', 'timeGetTime']
            
            time_checks = []
            for call in self.api_calls:
                if any(api in call['api'] for api in time_apis):
                    time_checks.append(call['api'])
            
            if time_checks:
                evidence.append(f"Found system time checks: {', '.join(time_checks)}")
                
        return evidence
    
    def _detect_process_injection(self):
        """Detect process injection techniques"""
        evidence = []
        
        if hasattr(self, 'api_calls') and self.api_calls:
            # Common APIs used for process injection
            injection_apis = {
                'memory_allocation': ['VirtualAllocEx', 'NtAllocateVirtualMemory', 'ZwAllocateVirtualMemory'],
                'memory_writing': ['WriteProcessMemory', 'NtWriteVirtualMemory', 'ZwWriteVirtualMemory'],
                'execution': ['CreateRemoteThread', 'NtCreateThreadEx', 'ZwCreateThreadEx', 
                             'QueueUserAPC', 'NtQueueApcThread', 'RtlCreateUserThread'],
                'dll_injection': ['LoadLibrary', 'LoadLibraryEx', 'LdrLoadDll'],
                'handle_access': ['OpenProcess', 'NtOpenProcess', 'ZwOpenProcess']
            }
            
            detected_techniques = {}
            
            for technique, apis in injection_apis.items():
                detected_apis = []
                for call in self.api_calls:
                    if any(api in call['api'] for api in apis):
                        detected_apis.append(call['api'])
                
                if detected_apis:
                    detected_techniques[technique] = detected_apis
            
            # Check for process injection patterns (sequence of calls)
            if ('handle_access' in detected_techniques and 
                'memory_allocation' in detected_techniques and 
                'memory_writing' in detected_techniques and 
                'execution' in detected_techniques):
                evidence.append("Detected complete process injection pattern")
                
            # Add individual suspicious API calls
            for technique, apis in detected_techniques.items():
                evidence.append(f"Detected {technique} APIs: {', '.join(apis)}")
                
            # Check for shellcode characteristics in written memory
            if hasattr(self, 'memory_writes') and self.memory_writes:
                for write in self.memory_writes:
                    # Look for common shellcode patterns (e.g., egg hunters, API resolvers)
                    if len(write['data']) > 20 and self._is_potential_shellcode(write['data']):
                        evidence.append(f"Potential shellcode detected in memory write to {write['address']}")
                        
        return evidence
    
    def _is_potential_shellcode(self, data):
        """Heuristic detection of potential shellcode"""
        # Common shellcode characteristics
        indicators = [
            b'\xfc\xe8',  # Start of 32-bit shellcode (common prologue)
            b'\x31\xc0',  # xor eax, eax
            b'\x33\xc0',  # xor eax, eax (MSVC style)
            b'\x48\x31\xc0',  # xor rax, rax (64-bit)
            b'\x48\x83\xec',  # sub rsp, X (stack space allocation)
            b'\x90\x90\x90',  # NOP sleds
            b'\xeb\xfe',  # Infinite loop (jmp $-2)
            b'\xe9',      # Near jump
            b'\xff\x34',  # Push dword ptr
            b'\x68'       # Push immediate (common in shellcode)
        ]
        
        # Check for shellcode indicators
        for indicator in indicators:
            if indicator in data:
                return True
                
        # Check for high entropy (common in encoded/encrypted shellcode)
        if len(data) > 50:
            entropy = self._calculate_entropy(data)
            if entropy > 6.5:  # High entropy threshold
                return True
                
        return False
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
                
        return entropy
    
    def _detect_code_obfuscation(self, sample_path):
        """Detect code obfuscation techniques"""
        evidence = []
        
        try:
            with open(sample_path, 'rb') as f:
                content = f.read()
                
            # Check for high entropy sections
            if len(content) > 1000:
                entropy = self._calculate_entropy(content)
                if entropy > 7.0:
                    evidence.append(f"Unusually high entropy: {entropy:.2f} (possible packed/encrypted code)")
            
            # Check for known packers/obfuscators
            packer_strings = [
                'UPX', 'ASPack', 'PECompact', 'MPRESS', 'Themida', 'VMProtect',
                'Armadillo', 'Obsidium', 'Enigma', 'ExeCryptor', '.netshrink',
                'Confuser', 'ConfuserEx', '.NET Reactor', 'SmartAssembly'
            ]
            
            for packer in packer_strings:
                if packer.encode() in content:
                    evidence.append(f"Potential {packer} packer detected")
            
            # Check for suspicious section names
            suspicious_sections = [b'.UPXS', b'UPX1', b'UPX2', b'.aspack', b'.adata', b'.packed']
            for section in suspicious_sections:
                if section in content:
                    evidence.append(f"Suspicious section name detected: {section.decode()}")
                    
            # Anti-disassembly techniques
            anti_disasm = [
                b'\xeb\x02', b'\xeb\x04',  # Short jumps to middle of instruction
                b'\xe8\x00\x00\x00\x00'    # Call+0 (get EIP technique)
            ]
            
            for technique in anti_disasm:
                if technique in content:
                    evidence.append("Potential anti-disassembly technique detected")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error during code obfuscation detection: {e}")
            
        return evidence
    
    def _detect_network_evasion(self):
        """Detect network-based evasion techniques"""
        evidence = []
        
        if hasattr(self, 'network_activity') and self.network_activity:
            # Check for DNS tunneling indicators
            unusual_dns = []
            for request in self.network_activity:
                if 'type' in request and request['type'] == 'dns':
                    # Check for unusually long DNS queries
                    if 'query' in request and len(request['query']) > 50:
                        unusual_dns.append(request['query'])
                    
                    # Check for high volume of DNS queries
                    if len([r for r in self.network_activity if r.get('type') == 'dns']) > 20:
                        evidence.append("Unusually high volume of DNS queries (potential DNS tunneling)")
            
            if unusual_dns:
                evidence.append(f"Unusually long DNS queries detected (potential DNS tunneling)")
            
            # Check for direct IP connections (bypassing DNS)
            ip_connections = []
            for request in self.network_activity:
                if 'type' in request and request['type'] == 'tcp' and 'destination_ip' in request:
                    if self._is_direct_ip_connection(request['destination_ip']):
                        ip_connections.append(request['destination_ip'])
            
            if ip_connections:
                evidence.append(f"Direct IP connections detected: {', '.join(ip_connections[:5])}")
                
            # Check for TOR/proxy connections
            for request in self.network_activity:
                if 'destination_ip' in request and self._is_tor_node(request['destination_ip']):
                    evidence.append(f"Potential TOR network connection to {request['destination_ip']}")
                
        return evidence
    
    def _is_direct_ip_connection(self, ip):
        """Check if the connection uses a direct IP instead of domain name"""
        # Simplified check: just verify it's an IP address
        import re
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        return bool(ip_pattern.match(ip))
    
    def _is_tor_node(self, ip):
        """Check if IP is a known TOR exit node (simplified)"""
        # In a real implementation, this would check against a TOR exit node database
        # For this example, we'll use a simplified approach with a few known TOR exit node IPs
        known_tor_nodes = [
            '192.42.116.16', '199.249.230.', '204.13.164.', '171.25.193.', '185.220.101.'
        ]
        
        return any(ip.startswith(node) for node in known_tor_nodes)
    
    def _detect_sandbox_detection(self):
        """Detect sandbox detection techniques"""
        evidence = []
        
        if hasattr(self, 'api_calls') and self.api_calls:
            # Common sandbox detection techniques through API calls
            sandbox_apis = {
                'system_information': ['GetSystemInfo', 'GlobalMemoryStatusEx', 'GetDiskFreeSpaceEx'],
                'user_interaction': ['GetCursorPos', 'GetAsyncKeyState', 'GetKeyState', 'GetUserNameA'],
                'hardware_checks': ['GetSystemMetrics', 'EnumDisplayDevices', 'EnumDisplayMonitors'],
                'filesystem_checks': ['GetVolumeInformation', 'GetDriveType', 'FindFirstFile'],
                'process_checks': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next']
            }
            
            detected_techniques = {}
            
            for technique, apis in sandbox_apis.items():
                detected_apis = []
                for call in self.api_calls:
                    if any(api in call['api'] for api in apis):
                        detected_apis.append(call['api'])
                
                if detected_apis:
                    detected_techniques[technique] = detected_apis
            
            # Add detected sandbox detection techniques
            for technique, apis in detected_techniques.items():
                evidence.append(f"Potential sandbox detection - {technique}: {', '.join(apis)}")
            
            # Check for suspicious process enumeration (looking for analysis tools)
            analysis_tools = ['wireshark', 'procmon', 'processhacker', 'ollydbg', 'immunity', 
                             'ida', 'x64dbg', 'pestudio', 'autoruns', 'tcpview']
            
            for call in self.api_calls:
                if 'arguments' in call and isinstance(call['arguments'], dict):
                    for arg_value in call['arguments'].values():
                        if isinstance(arg_value, str) and any(tool in arg_value.lower() for tool in analysis_tools):
                            evidence.append(f"Checking for analysis tool: {arg_value}")
        
        return evidence
    
    def _detect_memory_artifacts(self):
        """Detect memory evasion and manipulation techniques"""
        evidence = []
        
        if hasattr(self, 'api_calls') and self.api_calls:
            # Memory protection modifications
            mem_protection_apis = ['VirtualProtect', 'VirtualProtectEx', 'NtProtectVirtualMemory']
            
            for call in self.api_calls:
                if any(api in call['api'] for api in mem_protection_apis):
                    # Check for making memory regions executable
                    if 'arguments' in call and isinstance(call['arguments'], dict):
                        for arg_name, arg_value in call['arguments'].items():
                            if 'protect' in arg_name.lower() and 'exec' in str(arg_value).lower():
                                evidence.append(f"Modifying memory protection to executable: {call['api']}")
            
            # Self-modifying code
            if hasattr(self, 'memory_writes') and self.memory_writes:
                for write in self.memory_writes:
                    if 'source_region' in write and 'destination_region' in write:
                        if write['source_region'] == write['destination_region']:
                            evidence.append(f"Potential self-modifying code detected: writing to own memory region")
            
            # Process hollowing/replacement detection
            replacement_pattern = []
            for call in self.api_calls:
                if 'ZwUnmapViewOfSection' in call['api'] or 'NtUnmapViewOfSection' in call['api']:
                    replacement_pattern.append('unmap')
                elif 'VirtualAllocEx' in call['api'] and replacement_pattern and replacement_pattern[-1] == 'unmap':
                    replacement_pattern.append('alloc')
                elif 'WriteProcessMemory' in call['api'] and replacement_pattern and replacement_pattern[-1] == 'alloc':
                    replacement_pattern.append('write')
                elif 'SetThreadContext' in call['api'] and replacement_pattern and replacement_pattern[-1] == 'write':
                    replacement_pattern.append('setcontext')
                elif 'ResumeThread' in call['api'] and replacement_pattern and replacement_pattern[-1] == 'setcontext':
                    evidence.append("Process hollowing technique detected (complete pattern)")
                    break
            
            if len(replacement_pattern) >= 3:
                evidence.append(f"Partial process hollowing pattern detected: {' -> '.join(replacement_pattern)}")
        
        return evidence

# Example usage
if __name__ == "__main__":
    analyzer = DynamicAnalyzer(timeout=30)
    
    # Example file path - should be replaced with actual file to analyze
    test_file = "path/to/test/file.exe"
    
    if os.path.exists(test_file):
        results = analyzer.analyze_file(test_file)
        print(json.dumps(results, indent=2))
    else:
        print(f"Test file not found: {test_file}") 