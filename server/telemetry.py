"""PS5 hardware, storage and running-game telemetry for the Overview dashboard."""
import hashlib
import logging
from pathlib import Path
import posixpath
import re
import threading
import time
import urllib.parse

from power import PowerError
from titles import extract_id

_TITLE_ID = re.compile(r'(?:CUSA|PPSA|PCAS|PCJS|PLAS|PLJS|NPXS)\d{5}\Z')
_PNG = b'\x89PNG\r\n\x1a\n'
_JPEG = b'\xff\xd8\xff'
_MAX_COVER = 2 << 20


def _num(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().rstrip('%')
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _pick(mappings, keys):
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        for key in keys:
            if key in mapping and mapping[key] is not None and mapping[key] != '':
                return mapping[key]
    return None


def _bytes_value(mappings, byte_keys=(), mb_keys=(), gb_keys=()):
    v = _num(_pick(mappings, byte_keys))
    if v is not None and v >= 0:
        return int(v)
    v = _num(_pick(mappings, mb_keys))
    if v is not None and v >= 0:
        return int(v * 1024 * 1024)
    v = _num(_pick(mappings, gb_keys))
    if v is not None and v >= 0:
        return int(v * 1024 * 1024 * 1024)
    return None


def _classify_volume(path, raw_label=''):
    p = str(path or '').rstrip('/') or '/'
    if p.startswith('/mnt/ext'):
        return '扩展 M.2 存储', 'M.2'
    if p.startswith('/mnt/usb'):
        return '外置 USB 存储', 'USB'
    if p in ('/data', '/user') or p.startswith(('/data/', '/user/')):
        return '内置存储', 'SSD'
    label = str(raw_label or '').strip()
    if label:
        return label, 'DISK'
    return p, 'DISK'


def _image_kind(data):
    if not data or len(data) > _MAX_COVER:
        return None
    if data.startswith(_PNG):
        return 'image/png', '.png'
    if data.startswith(_JPEG):
        return 'image/jpeg', '.jpg'
    return None


class ConsoleTelemetry:
    """Collect PS5 hardware metrics, storage volumes and active game info."""

    def __init__(self, engine, files=None, library=None, titles=None, data_dir=None, cache_ttl=4.0):
        self.engine = engine
        self.files = files
        self.library = library
        self.titles = titles
        self.covers_dir = Path(data_dir) / 'telemetry-covers' if data_dir else None
        self.cache_ttl = float(cache_ttl)
        self.lock = threading.Lock()
        self.cache = {}

    def _engine_get(self, path, addr, timeout=2.8):
        if self.engine is None:
            return None, False
        url = f'{path}?{urllib.parse.urlencode({"addr": addr})}'
        try:
            data = self.engine.request('GET', url, timeout=timeout)
        except PowerError:
            return None, False
        except Exception as exc:
            logging.debug('telemetry engine call %s failed: %s', path, exc)
            return None, False
        if not isinstance(data, dict) or data.get('ok') is False or data.get('error'):
            return data if isinstance(data, dict) else None, True
        return data, True

    def _parse_cpu(self, hw, temps, power_raw):
        sources = [hw.get('cpu'), temps, power_raw, hw]
        freq_ghz = _num(_pick(sources, ('freq_ghz', 'cpu_freq_ghz')))
        if freq_ghz is None:
            mhz = _num(_pick(sources, ('freq_mhz', 'cpu_freq_mhz', 'clock_mhz', 'cpu_clock_mhz')))
            if mhz is not None and mhz >= 0:
                freq_ghz = round(mhz / 1000.0, 2)
        cores = _num(_pick(sources, ('logical_cores', 'cores', 'cpu_cores', 'threads')))
        temp_c = _num(_pick(sources, ('temp_c', 'cpu_temp', 'cpu_temp_c', 'package_temp_c')))
        soc_temp_c = _num(_pick(sources, ('soc_temp_c', 'soc_temp', 'apu_temp_c')))
        power_w = _num(_pick(sources, ('power_w', 'cpu_power_w', 'soc_power_w', 'total_power_w', 'power')))
        power_note = str(_pick(sources, ('power_note',)) or '')
        if not power_note and power_w is not None:
            power_note = '整机 SoC 估算'
        load_pct = _num(_pick(sources, ('load_pct', 'cpu_load', 'cpu_usage', 'usage_pct', 'usage')))
        fan_pct = _num(_pick(sources, ('fan_pct', 'fan_duty', 'fan_speed_pct', 'fan_percent')))
        return {
            'freq_ghz': round(freq_ghz, 2) if freq_ghz is not None else None,
            'cores': int(cores) if cores is not None and cores > 0 else None,
            'temp_c': round(temp_c, 1) if temp_c is not None else None,
            'soc_temp_c': round(soc_temp_c, 1) if soc_temp_c is not None else None,
            'power_w': round(power_w, 1) if power_w is not None else None,
            'power_note': power_note,
            'load_pct': round(max(0.0, min(100.0, load_pct)), 1) if load_pct is not None else None,
            'fan_pct': round(max(0.0, min(100.0, fan_pct)), 1) if fan_pct is not None else None,
        }

    def _parse_memory(self, hw):
        mem = hw.get('memory') if isinstance(hw.get('memory'), dict) else {}
        ram = hw.get('ram') if isinstance(hw.get('ram'), dict) else {}
        sources = [mem, ram, hw]
        used = _bytes_value(sources,
                            byte_keys=('used_bytes', 'mem_used_bytes'),
                            mb_keys=('used_mb', 'mem_used_mb'),
                            gb_keys=('used_gb', 'mem_used_gb'))
        total = _bytes_value(sources,
                             byte_keys=('total_bytes', 'mem_total_bytes'),
                             mb_keys=('total_mb', 'mem_total_mb'),
                             gb_keys=('total_gb', 'mem_total_gb'))
        direct = _bytes_value(sources,
                              byte_keys=('direct_memory_bytes', 'direct_bytes', 'dmem_bytes', 'vram_pool_bytes'),
                              mb_keys=('direct_memory_mb', 'dmem_mb'),
                              gb_keys=('direct_memory_gb', 'dmem_gb'))
        swap = _bytes_value(sources,
                            byte_keys=('swap_bytes', 'swap_used_bytes'),
                            mb_keys=('swap_mb',),
                            gb_keys=('swap_gb',))
        wired = _bytes_value(sources,
                             byte_keys=('wired_bytes', 'resident_bytes', 'kernel_bytes'),
                             mb_keys=('wired_mb', 'resident_mb'),
                             gb_keys=('wired_gb',))
        pct = _num(_pick(sources, ('used_pct', 'percent', 'mem_pct')))
        if pct is None and used is not None and total and total > 0:
            pct = round((used / total) * 100.0, 1)
        elif pct is not None:
            pct = round(max(0.0, min(100.0, pct)), 1)
        note = str(_pick(sources, ('note', 'mem_note')) or '')
        return {
            'used_bytes': used,
            'total_bytes': total,
            'direct_bytes': direct,
            'swap_bytes': swap,
            'wired_bytes': wired,
            'used_pct': pct,
            'note': note,
        }

    def _parse_volumes(self, hw, engine_vols, ip):
        raw_list = []
        for src in (hw.get('volumes'), engine_vols.get('volumes') if isinstance(engine_vols, dict) else None):
            if isinstance(src, list) and src:
                raw_list = src
                break
        if not raw_list and self.files is not None and getattr(self.files, 'host', '') == ip:
            try:
                fvols = self.files.volumes()
                raw_list = fvols.get('volumes') or []
            except Exception:
                raw_list = []
        volumes = []
        seen_paths = set()
        has_data = False
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or item.get('mount') or item.get('name') or '').strip()
            if not path or path in seen_paths:
                continue
            # Prefer /data over /user if both map to internal storage unless /data is absent.
            if path == '/data':
                has_data = True
            seen_paths.add(path)
            total = _bytes_value([item], ('total_bytes', 'size_bytes', 'total', 'size'), ('total_mb',), ('total_gb',))
            free = _bytes_value([item], ('free_bytes', 'avail_bytes', 'available_bytes', 'free'), ('free_mb',), ('free_gb',))
            used = _bytes_value([item], ('used_bytes', 'used'), ('used_mb',), ('used_gb',))
            if used is None and total is not None and free is not None:
                used = max(0, total - free)
            elif free is None and total is not None and used is not None:
                free = max(0, total - used)
            if total is None or total <= 0:
                continue
            pct = _num(item.get('percent'))
            if pct is None and used is not None:
                pct = (used / total) * 100.0
            label, kind = _classify_volume(path, item.get('label'))
            volumes.append({
                'path': path,
                'label': label,
                'kind': kind,
                'used_bytes': used if used is not None else 0,
                'total_bytes': total,
                'free_bytes': free if free is not None else max(0, total - (used or 0)),
                'percent': round(max(0.0, min(100.0, pct or 0.0)), 1),
            })
        if has_data:
            volumes = [v for v in volumes if v['path'] != '/user']
        order = {'SSD': 0, 'USB': 1, 'M.2': 2, 'DISK': 3}
        volumes.sort(key=lambda v: (order.get(v['kind'], 9), v['path']))
        return volumes

    def _find_library_game(self, title_id):
        if not title_id or self.library is None:
            return None
        with getattr(self.library, 'lock', threading.Lock()):
            cached = getattr(self.library, 'cached', None)
        if not isinstance(cached, dict):
            return None
        for game in cached.get('games') or []:
            if isinstance(game, dict) and game.get('title') == title_id:
                return game
        return None

    def _cache_cover(self, title_id, ip):
        if not title_id or not _TITLE_ID.fullmatch(title_id):
            return ''
        if self.covers_dir:
            for ext in ('.png', '.jpg'):
                existing = self.covers_dir / f'{title_id}{ext}'
                if existing.is_file():
                    return f'/api/ps5/telemetry/cover?title={title_id}'
        # Try FileProxy or library cover cache when host matches.
        lib_game = self._find_library_game(title_id)
        candidates = []
        if lib_game and lib_game.get('path'):
            candidates.append(posixpath.join(lib_game['path'].rstrip('/'), 'sce_sys', 'icon0.png'))
        candidates.extend((
            f'/data/shadowmount/icon-cache/{title_id}.png',
            f'/data/shadowmount/icon-cache/{title_id}/icon0.png',
            f'/user/appmeta/{title_id}/icon0.png',
            f'/user/app/{title_id}/sce_sys/icon0.png',
        ))
        if self.files is not None and getattr(self.files, 'host', '') == ip and self.covers_dir:
            for path in candidates:
                try:
                    data = self.files.read_bytes(path, limit=_MAX_COVER)
                except Exception:
                    continue
                kind = _image_kind(data)
                if kind:
                    _, ext = kind
                    try:
                        self.covers_dir.mkdir(parents=True, exist_ok=True)
                        target = self.covers_dir / f'{title_id}{ext}'
                        tmp = target.with_suffix('.tmp')
                        tmp.write_bytes(data)
                        tmp.replace(target)
                        return f'/api/ps5/telemetry/cover?title={title_id}'
                    except OSError:
                        return ''
        if lib_game and lib_game.get('has_cover') and lib_game.get('path'):
            return f'/api/library/icon?{urllib.parse.urlencode({"path": lib_game["path"]})}'
        return ''

    def cover(self, title_id):
        if not isinstance(title_id, str) or not _TITLE_ID.fullmatch(title_id):
            raise ValueError('游戏编号无效')
        if self.covers_dir:
            for ext, ctype in (('.png', 'image/png'), ('.jpg', 'image/jpeg')):
                path = self.covers_dir / f'{title_id}{ext}'
                if path.is_file():
                    data = path.read_bytes()
                    etag = '"' + hashlib.sha256(data).hexdigest()[:16] + '"'
                    return data, etag, ctype
        raise FileNotFoundError('暂无游戏封面')

    def _parse_game(self, ip, hw, fps_raw, power_info):
        game_obj = hw.get('game') if isinstance(hw.get('game'), dict) else (
            hw.get('running_game') if isinstance(hw.get('running_game'), dict) else {}
        )
        sources = [game_obj, fps_raw, hw]
        raw_id = str(_pick(sources, ('title_id', 'app_id', 'id')) or (power_info or {}).get('running_app_id') or '').strip()
        title_id = extract_id(raw_id) or (raw_id if _TITLE_ID.fullmatch(raw_id) else '')
        raw_name = str(_pick(sources, ('title_name', 'name', 'title', 'app_name'))
                       or (power_info or {}).get('running_app') or '').strip()
        fps = _num(_pick(sources, ('fps', 'current_fps', 'frame_rate')))
        developer = str(_pick(sources, ('developer', 'publisher', 'vendor')) or '').strip()
        genre = str(_pick(sources, ('genre', 'category')) or '').strip()
        description = str(_pick(sources, ('description', 'summary', 'overview')) or '').strip()

        catalog_entry = self.titles.entry(title_id) if (title_id and self.titles is not None) else None
        title_zh = (catalog_entry or {}).get('zh', '')
        title_en = (catalog_entry or {}).get('en', '')
        display_name = title_zh or raw_name or title_en or title_id
        if not title_en and raw_name and raw_name != display_name:
            title_en = raw_name

        running = bool(title_id or raw_name or fps is not None)
        cover_url = self._cache_cover(title_id, ip) if running and title_id else ''
        return {
            'running': running,
            'state_label': '运行中' if running else '空闲',
            'title_id': title_id,
            'name': display_name,
            'title_zh': title_zh or (display_name if title_zh else ''),
            'title_en': title_en,
            'fps': int(round(fps)) if fps is not None and fps >= 0 else None,
            'developer': developer,
            'genre': genre,
            'description': description,
            'cover_url': cover_url,
        }

    def collect(self, ip, validate_ip=None, power_info=None, force=False):
        if validate_ip is not None:
            ip = validate_ip(ip)
        now = time.monotonic()
        with self.lock:
            cached = self.cache.get(ip)
            if not force and cached and now - cached['ts'] < self.cache_ttl:
                return dict(cached['data'], cached=True)

        hw, engine_up = self._engine_get('/api/ps5/hw/info', ip, timeout=3.0)
        hw = hw if isinstance(hw, dict) else {}
        hw_error = str(hw.get('error') or '') if hw.get('error') or hw.get('ok') is False else ''

        temps = {}
        power_raw = {}
        engine_vols = {}
        fps_raw = {}

        if engine_up and not hw_error:
            cpu_hint = hw.get('cpu') if isinstance(hw.get('cpu'), dict) else hw
            if _pick([cpu_hint], ('temp_c', 'cpu_temp', 'cpu_temp_c')) is None:
                t, _ = self._engine_get('/api/ps5/hw/temps', ip, timeout=1.8)
                if isinstance(t, dict):
                    temps = t
            if _pick([cpu_hint], ('power_w', 'cpu_power_w', 'soc_power_w')) is None:
                p, _ = self._engine_get('/api/ps5/hw/power', ip, timeout=1.8)
                if isinstance(p, dict):
                    power_raw = p
            if not isinstance(hw.get('volumes'), list):
                v, _ = self._engine_get('/api/ps5/volumes', ip, timeout=2.0)
                if isinstance(v, dict):
                    engine_vols = v
            game_hint = hw.get('game') if isinstance(hw.get('game'), dict) else hw
            if _pick([game_hint], ('fps', 'current_fps')) is None:
                f, _ = self._engine_get('/api/ps5/hw/fps', ip, timeout=1.2)
                if isinstance(f, dict):
                    fps_raw = f

        cpu = self._parse_cpu(hw if not hw_error else {}, temps, power_raw)
        memory = self._parse_memory(hw if not hw_error else {})
        volumes = self._parse_volumes(hw if not hw_error else {}, engine_vols, ip)
        game = self._parse_game(ip, hw if not hw_error else {}, fps_raw, power_info)

        has_hw = any(cpu[k] is not None for k in ('freq_ghz', 'temp_c', 'power_w', 'load_pct')) or any(
            memory[k] is not None for k in ('used_bytes', 'total_bytes', 'direct_bytes', 'used_pct'))
        result = {
            'host': ip,
            'engine_available': engine_up,
            'has_hw': has_hw,
            'error': hw_error,
            'power_state': (power_info or {}).get('state') or '',
            'host_name': (power_info or {}).get('name') or str(hw.get('host_name') or hw.get('name') or ''),
            'firmware': (power_info or {}).get('firmware') or str(hw.get('firmware') or hw.get('sdk_version') or ''),
            'cpu': cpu,
            'memory': memory,
            'volumes': volumes,
            'game': game,
            'updated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'cached': False,
        }
        with self.lock:
            self.cache[ip] = {'ts': time.monotonic(), 'data': result}
        return dict(result)
