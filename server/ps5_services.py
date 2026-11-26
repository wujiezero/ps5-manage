"""PS5 open ELF port scanner and GitHub homebrew service catalog."""
import concurrent.futures
import html
import re
import socket
import threading
import time

# Known PS5 homebrew ELF ports compiled from GitHub projects (ps5-payload-dev,
# itsPLK, phantomptr, owendswang, etaHEN, SiSTR0, tom-ps5-usbnet, etc.).
KNOWN_SERVICES = {
    8084: {
        'id': 'pldmgr',
        'name': 'Payload Manager',
        'category': 'Loader',
        'description': '网页版载荷与自启动管理面板',
        'repo': 'itsPLK/ps5-payload-manager',
        'protocol': 'http',
        'web': True,
    },
    8888: {
        'id': 'web-file-manager',
        'name': 'Web File Manager',
        'category': 'Files',
        'description': '浏览器文件管理与存储容量查看',
        'repo': 'owendswang/ps5-web-file-manager',
        'protocol': 'http',
        'web': True,
    },
    8080: {
        'id': 'websrv',
        'name': 'Web Server (websrv)',
        'category': 'Web',
        'description': 'PS5 HTTP 后台与自制应用商店接口',
        'repo': 'ps5-payload-dev/websrv',
        'protocol': 'http',
        'web': True,
    },
    80: {
        'id': 'http-filesrv',
        'name': 'PS5 HTTP 文件服务',
        'category': 'Files',
        'description': 'USBNet / HTTP 文件浏览与高速传输服务',
        'repo': 'tom-ps5-usbnet',
        'protocol': 'http',
        'web': True,
    },
    9090: {
        'id': 'etahen-toolbox',
        'name': 'etaHEN / Web RPC',
        'category': 'Loader',
        'description': 'etaHEN 网页调试 / Webkit 入口服务',
        'repo': 'etaHEN/etaHEN',
        'protocol': 'tcp',
        'web': False,
    },
    9113: {
        'id': 'ps5upload',
        'name': 'ps5upload Daemon',
        'category': 'Files',
        'description': 'ps5upload 高速传输与主机遥测守护进程',
        'repo': 'phantomptr/ps5upload',
        'protocol': 'tcp',
        'web': False,
    },
    9021: {
        'id': 'elfldr',
        'name': 'ELF Loader (elfldr)',
        'category': 'Loader',
        'description': 'ELF 载荷注入端口（TCP 直传运行）',
        'repo': 'ps5-payload-dev/elfldr',
        'protocol': 'tcp',
        'web': False,
    },
    9020: {
        'id': 'shsrv',
        'name': 'Shell / Payload Loader',
        'category': 'Loader',
        'description': 'ps5-payload-dev 远程 Shell 或初始载荷端口',
        'repo': 'ps5-payload-dev/shsrv',
        'protocol': 'tcp',
        'web': False,
    },
    2121: {
        'id': 'ftpsrv',
        'name': 'FTP Server (ftpsrv)',
        'category': 'Files',
        'description': 'ps5-payload-dev 标准 FTP 文件服务',
        'repo': 'ps5-payload-dev/ftpsrv',
        'protocol': 'ftp',
        'web': False,
    },
    2120: {
        'id': 'zftpd',
        'name': 'FTP Server (zftpd)',
        'category': 'Files',
        'description': 'zftpd 文件传输服务',
        'repo': 'zftpd / ps5-payload-dev',
        'protocol': 'ftp',
        'web': False,
    },
    1337: {
        'id': 'etahen-ftp',
        'name': 'etaHEN FTP Server',
        'category': 'Files',
        'description': 'etaHEN 内置 FTP 服务端口',
        'repo': 'etaHEN/etaHEN',
        'protocol': 'ftp',
        'web': False,
    },
    3232: {
        'id': 'klogsrv',
        'name': 'Kernel Log Server (klogsrv)',
        'category': 'Diagnostics',
        'description': 'PS5 内核日志实时输出端口',
        'repo': 'ps5-payload-dev/klogsrv',
        'protocol': 'tcp',
        'web': False,
    },
    9081: {
        'id': 'klogsrv-alt',
        'name': 'Kernel Log Stream',
        'category': 'Diagnostics',
        'description': '备用内核日志流端口',
        'repo': 'ps5-payload-dev/klogsrv',
        'protocol': 'tcp',
        'web': False,
    },
    9045: {
        'id': 'ps5debug',
        'name': 'ps5debug',
        'category': 'Diagnostics',
        'description': '进程内存与断点调试服务',
        'repo': 'SiSTR0/ps5debug',
        'protocol': 'tcp',
        'web': False,
    },
    2323: {
        'id': 'shell-telnet',
        'name': 'Shell Server (Telnet)',
        'category': 'System',
        'description': '交互式控制台端口',
        'repo': 'ps5-payload-dev/shsrv',
        'protocol': 'tcp',
        'web': False,
    },
    9027: {
        'id': 'etahen-ipc',
        'name': 'etaHEN IPC / DPI',
        'category': 'System',
        'description': 'etaHEN 内部命令或 DPI 接收端口',
        'repo': 'etaHEN/etaHEN',
        'protocol': 'tcp',
        'web': False,
    },
    12800: {
        'id': 'dpi-v2',
        'name': 'Direct Package Installer',
        'category': 'Files',
        'description': '远程 PKG 推送安装端口',
        'repo': 'DirectPackageInstaller / etaHEN',
        'protocol': 'http',
        'web': True,
    },
}

# Process-name fallback keywords -> match running ELF names when hints are helpful.
PROCESS_HINTS = (
    ('pldmgr', 'pldmgr'),
    ('web-file-mgr', 'web-file-manager'),
    ('websrv', 'websrv'),
    ('ps5upload', 'ps5upload'),
    ('ftpsrv', 'ftpsrv'),
    ('zftpd', 'zftpd'),
    ('klogsrv', 'klogsrv'),
    ('shsrv', 'shsrv'),
    ('elfldr', 'elfldr'),
    ('etahen', 'etahen-toolbox'),
)

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)


def _tcp_open(ip, port, timeout=0.45):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def probe_http(ip, port, timeout=0.8):
    """Best-effort HTTP GET / probe on an open TCP port.

    Returns {'is_http': bool, 'title': str, 'server': str, 'content_type': str}.
    """
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            req = f'GET / HTTP/1.0\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n'.encode('ascii')
            sock.sendall(req)
            chunks = []
            remaining = 16384
            while remaining > 0:
                chunk = sock.recv(min(4096, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
    except OSError:
        return {'is_http': False, 'title': '', 'server': '', 'content_type': ''}
    raw = b''.join(chunks)
    if not raw.startswith(b'HTTP/1.') and not raw.startswith(b'HTTP/2'):
        return {'is_http': False, 'title': '', 'server': '', 'content_type': ''}
    head_bytes, _, body_bytes = raw.partition(b'\r\n\r\n')
    headers = {}
    for line in head_bytes.decode('latin-1', errors='replace').splitlines()[1:]:
        k, sep, v = line.partition(':')
        if sep:
            headers[k.strip().lower()] = v.strip()
    body = body_bytes.decode('utf-8', errors='replace')
    match = _TITLE_RE.search(body)
    title = re.sub(r'\s+', ' ', html.unescape(match.group(1))).strip()[:80] if match else ''
    return {
        'is_http': True,
        'title': title,
        'server': headers.get('server', '')[:64],
        'content_type': headers.get('content-type', '').split(';', 1)[0].strip().lower(),
    }


def _now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%S%z')


class PortScanner:
    """Scan open homebrew ELF TCP ports on a remembered/online PS5 host."""

    def __init__(self, validate_ip, cache_ttl=30.0, tcp_probe=_tcp_open, http_probe=probe_http,
                 extra_ports=(), clock=time.monotonic):
        self.validate_ip = validate_ip
        self.cache_ttl = float(cache_ttl)
        self.tcp_probe = tcp_probe
        self.http_probe = http_probe
        self.clock = clock
        ports = list(KNOWN_SERVICES.keys())
        for p in extra_ports:
            try:
                pi = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= pi <= 65535 and pi not in ports:
                ports.append(pi)
        self.ports = tuple(ports)
        self.lock = threading.Lock()
        self.cache = {}

    def _service_record(self, ip, port, running_names=()):
        meta = KNOWN_SERVICES.get(port, {})
        http_info = {'is_http': False, 'title': '', 'server': '', 'content_type': ''}
        # Always probe HTTP for marked HTTP services and ambiguous RPC ports.
        if meta.get('web') or meta.get('protocol') == 'http' or port in (80, 8080, 8084, 8888, 9090, 12800):
            http_info = self.http_probe(ip, port, timeout=0.8)
        is_web = bool(http_info['is_http'] or meta.get('web'))
        protocol = 'http' if is_web else meta.get('protocol', 'tcp')
        name = meta.get('name') or (f'HTTP 服务 ({port})' if is_web else f'TCP 服务 ({port})')
        if not meta.get('name') and http_info.get('server'):
            name = http_info['server']
        svc_id = meta.get('id', f'port-{port}')
        process_match = ''
        for rname in running_names:
            lower = str(rname).lower()
            for kw, mapped_id in PROCESS_HINTS:
                if kw in lower and mapped_id == svc_id:
                    process_match = str(rname)
                    break
            if process_match:
                break
        if protocol == 'http':
            url = f'http://{ip}/' if port == 80 else f'http://{ip}:{port}/'
        elif protocol == 'ftp':
            url = f'ftp://{ip}:{port}/'
        else:
            url = f'{ip}:{port}'
        return {
            'port': port,
            'id': svc_id,
            'name': name,
            'category': meta.get('category', 'Web' if is_web else 'Other'),
            'description': meta.get('description', '检测到的开放端口服务'),
            'repo': meta.get('repo', ''),
            'protocol': protocol,
            'url': url,
            'web': is_web,
            'title': http_info.get('title') or '',
            'process': process_match,
        }

    def scan(self, ip, running_processes=(), force=False):
        ip = self.validate_ip(ip)
        now = self.clock()
        with self.lock:
            cached = self.cache.get(ip)
            if not force and cached and now - cached['ts'] < self.cache_ttl:
                return dict(cached['data'], cached=True)

        started = time.monotonic()
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(self.ports) or 1)) as pool:
            futures = {pool.submit(self.tcp_probe, ip, port, 0.45): port for port in self.ports}
            for future, port in futures.items():
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    continue
        open_ports.sort()

        running_names = [
            item.get('name') or '' for item in (running_processes or ())
            if isinstance(item, dict) and item.get('name')
        ]
        services = []
        if open_ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(open_ports))) as pool:
                services = list(pool.map(lambda p: self._service_record(ip, p, running_names), open_ports))

        result = {
            'host': ip,
            'online': bool(services),
            'services': services,
            'scanned_ports': len(self.ports),
            'scanned_at': _now_iso(),
            'duration_ms': int((time.monotonic() - started) * 1000),
            'cached': False,
        }
        with self.lock:
            self.cache[ip] = {'ts': self.clock(), 'data': result}
        return dict(result)
