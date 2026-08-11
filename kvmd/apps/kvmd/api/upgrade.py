import asyncio
import aiohttp
from aiohttp import web
from typing import Dict, Any
import os
import re
import zipfile
import io
import datetime
import json
import yaml
import shutil
import fnmatch
import glob
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor
from ....logging import get_logger
from .... import htclient

from ....htserver import exposed_http, make_json_exception, make_json_response, BadRequestError

UPGRADE_DIR = "/userdata/"
UPGRADE_FILE = "update.img"
EDID_FILE = "/tmp/edid.bin"
EDID_USER_FILE = "/etc/kvmd/user/edid.txt" # 用于保存当前写入的EDID
EDID_LIST_FILE = "/etc/kvmd/edid.json"
LOG_DIR = "/tmp/log"
# 与 aiohttp Application 默认 client_max_size(1MiB) 对齐；超出由框架返回 413
_FRONTEND_LOG_MAX_BYTES = 1024 * 1024
LT6911C_UPGRADE_CMD = "lt6911c_upgrade -d /dev/i2c-1 -e /tmp/edid.bin && sleep 1 && echo 1 >  /sys/bus/i2c/devices/1-002b/reset"
GSV1127X_UPGRADE_CMD = "echo 0 > /sys/bus/i2c/devices/1-0058/poll_interval_enable && sleep 1 " \
                            "&& gsv1127x_upgrade -d /dev/i2c-1 -e /tmp/edid.bin && sleep 1 " \
                            "&& echo 1 > /sys/bus/i2c/devices/1-0058/poll_interval_enable"
GSV1127_UPGRADE_CMD = "echo 0 > /sys/bus/i2c/devices/0-0058/enable_stream && sleep 0.5 " \
                            "&& gsv1127x_upgrade -d /dev/i2c-0 -e /tmp/edid.bin && sleep 0.5 " \
                            "&& echo 1 > /sys/bus/i2c/devices/0-0058/enable_stream"
MODEL_PATH = "/proc/gl-hw-info/model"
BASE_URL = "https://fw.gl-inet.com/kvm/{model}/release"
BETA_BASE_URL = "https://fw.gl-inet.com/kvm/{model}/testing"

# 以字面量 "." 开头只匹配 IPv4 后三段，借助 re 引擎的字面量前缀快速跳过，
# 避免在全文每个数字位置回溯试探；第一段由 _mask_public_ipv4 向前扩展补全并做边界检查。
_IPV4_TAIL_RE = re.compile(rb"\.(?:\d{1,3}\.){2}\d{1,3}(?![.\d])")

# 完整 IPv6 正则仅在 "::" 附近的小窗口内运行（见 _find_ipv6_spans），不做全文扫描
_IPV6_RE = re.compile(
    rb"(?<![:\w])(?:"
    rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    rb"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    rb"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    rb"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    rb"|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}"
    rb"|::1"
    rb"|::"
    rb")(?![:\w])"
)

# 完整形式 IPv6（8 组无压缩）必含 7 个冒号：以字面量 ":" 开头匹配后 7 组做快速跳过，
# 第一组由 _find_ipv6_spans 向前扩展补全并做边界检查。
_IPV6_FULL_TAIL_RE = re.compile(rb":(?:[0-9a-fA-F]{1,4}:){6}[0-9a-fA-F]{1,4}(?![:\w])")

_DIGIT_CHARS = frozenset(b"0123456789")
_HEX_CHARS = frozenset(b"0123456789abcdefABCDEF")
# IPv6 文本可能出现的字符（含 IPv4 映射形式的 "."）
_IPV6_TOKEN_CHARS = frozenset(b"0123456789abcdefABCDEF:.")
# "::" 窗口右边界须越过连续的 \w 字符，避免 finditer 的 endpos 截断让 (?![:\w]) 误判成功
_IPV6_WINDOW_CHARS = _IPV6_TOKEN_CHARS | frozenset(
    b"ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ_"
)

_SENSITIVE_RE = re.compile(rb'(?i)((?:auth_token|password)=)[^\s&"\']+')
_MASK_CHUNK_SIZE = 1024 * 1024

class LogCollector:
    def __init__(self, model: str, log_dir: str, config_path: str = "log_config.yaml"):
        self.__model = model
        self.LOG_DIR = log_dir
        self.config = self._load_or_create_config(config_path)
    
    def _load_or_create_config(self, config_path: str) -> Dict[str, Any]:
        """加载或创建配置文件"""
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                # 配置文件损坏，使用默认配置
                pass
        
        # 定义要收集的日志命令和对应的文件名
        default_config = {
            'base_commands': {
                'dmesg': 'dmesg_{timestamp}.log',
                'logread': 'logread_{timestamp}.log',
                'cat /userdata/log/messages /userdata/log/messages.* 2>/dev/null': 'logread_persist_{timestamp}.log',
                'cat /userdata/log/last_boot.log': 'logread_last_boot_{timestamp}.log',
                'lsusb': 'lsusb_{timestamp}.log',
                'ps auxww': 'ps_auxww_{timestamp}.log',
                'cat /proc/meminfo': 'meminfo_{timestamp}.log',
                'cat /etc/version': 'version_{timestamp}.log',
                'cat /proc/gl-hw-info/device_mac': 'device_mac_{timestamp}.log',
                'cat /etc/glinet/gl-cloud.conf': 'gl-cloud.conf_{timestamp}.log',
                'cat /etc/resolv.conf': 'resolv.conf_{timestamp}.log',
                'ifconfig': 'ifconfig_{timestamp}.log',
                'uptime': 'uptime_{timestamp}.log',
                'top -b -n 1 -o RES': 'top_{timestamp}.log',
                'wg': 'wg_{timestamp}.log',
                'connmanctl services': 'connman_services_{timestamp}.log',
                'connmanctl services 2>/dev/null | grep -oE "ethernet_[^ ]+" | head -1 | xargs -I{} connmanctl services {}': 'connman_eth0_{timestamp}.log',
                'connmanctl services 2>/dev/null | grep -oE "wifi_[^ ]+" | head -1 | xargs -I{} connmanctl services {}': 'connman_wifi_{timestamp}.log',
                '[ -f /sys/fs/pstore/console-ramoops-0 ] && cat /sys/fs/pstore/console-ramoops-0': 'console_ramoops_0_{timestamp}.log',
                '[ -f /sys/fs/pstore/dmesg-ramoops-0 ] && cat /sys/fs/pstore/dmesg-ramoops-0': 'dmesg_ramoops_0_{timestamp}.log',
                '[ -f /sys/fs/pstore/dmesg-ramoops-1 ] && cat /sys/fs/pstore/dmesg-ramoops-1': 'dmesg_ramoops_1_{timestamp}.log',
            },
            'model_commands': {
                'rm10rc': {
                    'ubus call repeater status && iw dev wlan0 info && iw dev wlan0 link': 'wifi_status_{timestamp}.log',
                    'ubus call repeater dump_surveys': 'wifi_channel_surveys_{timestamp}.json',
                    'ubus call modem status': 'modem_status_{timestamp}.log',
                },
                'rm10': {
                    'ubus call repeater status && iw dev wlan0 info && iw dev wlan0 link': 'wifi_status_{timestamp}.log',
                    'ubus call repeater dump_surveys': 'wifi_channel_surveys_{timestamp}.json',
                    'readreg_lt6911c.sh': 'lt6911c_regs_{timestamp}.log',
                },
                'rmq1': {
                    'ubus call repeater status && iw dev wlan0 info && iw dev wlan0 link': 'wifi_status_{timestamp}.log',
                    'ubus call repeater dump_surveys': 'wifi_channel_surveys_{timestamp}.json',
                    'cat /userdata/log/daemon.log*': 'daemon_{timestamp}.log',
                    'cat /userdata/log/kvmd.log*': 'kvmd_{timestamp}.log',
                    'cat /userdata/log/ax_user.log': 'ax_user_{timestamp}.log',
                    'cat /userdata/log/AXSyslog/syslog/*.log': 'ax_syslog_{timestamp}.log',
                    'axlogread': 'axlogread_{timestamp}.log',
                    'cat /userdata/swupdate.log': 'ax_swupdate_{timestamp}.log',
                    'cat /userdata/log/drp_upgrade.log': 'drp_upgrade_{timestamp}.log',
                    'cat /proc/ax_proc/mem_cmm_info': 'ax_mem_cmm_info_{timestamp}.log',
                    'cat /proc/ax_proc/pool': 'ax_pool_info_{timestamp}.log',
                    'cat /proc/ax_proc/vin/statistics': 'ax_vin_statistics_{timestamp}.log',
                    'cat /proc/ax_proc/venc': 'ax_venc_{timestamp}.log',
                }
            },
            # 需要脱敏处理的文件模式（glob 匹配），不在此列表的文件不做任何脱敏处理
            'sensitive_patterns': [
                '*ifconfig*',
                '*connman*',
                '*wg*',
                '*daemon*',
                '*kvmd*',
                '*ax_user*',
                '*ax_syslog*',
                '*logread*',
                '*modem_status*',
                '*frontend*',
            ],
        }
            
        return default_config
    
    @staticmethod
    @lru_cache(maxsize=65536)
    def _is_global_ipv4(ip_bytes: bytes) -> bool:
        try:
            parts = ip_bytes.split(b".")
            if len(parts) != 4:
                return False
            nums = tuple(int(part) for part in parts)
            if any(num < 0 or num > 255 for num in nums):
                return False
        except ValueError:
            return False

        first, second, third, fourth = nums
        if (
            first == 0
            or first == 10
            or first == 127
            or first >= 224
            or (first == 100 and 64 <= second <= 127)
            or (first == 169 and second == 254)
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
            or (first == 192 and second == 0 and third in (0, 2))
            or (first == 198 and second in (18, 19))
            or (first == 198 and second == 51 and third == 100)
            or (first == 203 and second == 0 and third == 113)
            or (first == 255 and second == 255 and third == 255 and fourth == 255)
        ):
            return False
        return True

    @staticmethod
    @lru_cache(maxsize=16384)
    def _is_global_ipv6(ip_bytes: bytes) -> bool:
        """快速判断 IPv6 地址是否为公网地址，使用前缀匹配替代 ipaddress 模块（性能提升 >10x）。"""
        if len(ip_bytes) < 2:
            return False
        if ip_bytes == b"::1":
            return False
        if ip_bytes == b"::":
            return False
        low = ip_bytes.lower()
        if low.startswith(b"::ffff:"):
            return LogCollector._is_global_ipv4(ip_bytes[7:])
        if low.startswith(b"ff"):
            return False
        if low[:1] == b"f" and len(low) > 1 and low[1:2] in (b"c", b"d"):
            return False
        if low.startswith(b"fe80"):
            return False
        if low.startswith(b"fec0"):
            return False
        return True

    @staticmethod
    def _mask_public_ipv4(content: bytes) -> bytes:
        """公网 IPv4 隐藏最后一段（1.2.3.4 → 1.2.3.*），私有地址保持不变。

        先用 _IPV4_TAIL_RE 定位候选（".x.x.x" 部分），再向前扩展第一个八位组，
        边界检查与原正则 (?<![.\\w])...(?![.\\d]) 语义一致。"""
        pieces = []
        pos = 0
        for m in _IPV4_TAIL_RE.finditer(content):
            start = m.start()
            first = start
            while first > 0 and start - first < 3 and content[first - 1] in _DIGIT_CHARS:
                first -= 1
            if first == start:
                continue
            prev = content[first - 1:first]
            if prev and (prev.isalnum() or prev in (b".", b"_")):  # 等价于 (?<![.\w])
                continue
            ip = content[first:m.end()]
            if not LogCollector._is_global_ipv4(ip):
                continue
            pieces.append(content[pos:first])
            pieces.append(ip[:ip.rfind(b".")] + b".*")
            pos = m.end()
        if not pieces:
            return content
        pieces.append(content[pos:])
        return b"".join(pieces)

    @staticmethod
    def _find_ipv6_spans(content: bytes) -> list:
        """定位所有公网 IPv6 的 (start, end) 区间，避免 _IPV6_RE 全文回溯扫描。

        压缩形式必含 "::"：用 bytes.find 定位后，仅在其所在 token 的窗口内跑完整正则。
        finditer 的 pos 不隔断 lookbehind（仍能看到窗口前的真实字符），窗口右界越过
        连续 \\w 保证 lookahead 语义，因此窗口内匹配结果与全文扫描一致。
        完整形式必含 7 个冒号：用 _IPV6_FULL_TAIL_RE 匹配后 7 组，再向前扩展第一组。"""
        spans = []
        length = len(content)

        search = 0
        while True:
            i = content.find(b"::", search)
            if i < 0:
                break
            lo = i
            while lo > 0 and content[lo - 1] in _IPV6_TOKEN_CHARS:
                lo -= 1
            hi = i + 2
            while hi < length and content[hi] in _IPV6_WINDOW_CHARS:
                hi += 1
            for m in _IPV6_RE.finditer(content, lo, hi):
                if LogCollector._is_global_ipv6(m.group(0)):
                    spans.append((m.start(), m.end()))
            search = hi

        for m in _IPV6_FULL_TAIL_RE.finditer(content):
            start = m.start()
            first = start
            while first > 0 and start - first < 4 and content[first - 1] in _HEX_CHARS:
                first -= 1
            if first == start:
                continue
            prev = content[first - 1:first]
            if prev and (prev.isalnum() or prev in (b"_", b":")):  # 等价于 (?<![:\w])
                continue
            if LogCollector._is_global_ipv6(content[first:m.end()]):
                spans.append((first, m.end()))

        return spans

    @staticmethod
    def _mask_public_ips(content: bytes, has_dot: bool = True, has_colon: bool = True) -> bytes:
        """公网 IPv4 隐藏最后一段（1.2.3.4 → 1.2.3.*），公网 IPv6 全部隐藏。
        根据预检查标志跳过不需要的扫描，避免无意义的全文匹配。"""
        if has_dot:
            content = LogCollector._mask_public_ipv4(content)
        if has_colon:
            spans = LogCollector._find_ipv6_spans(content)
            if spans:
                spans.sort()
                pieces = []
                pos = 0
                for start, end in spans:
                    if start < pos:  # 两条路径可能报出重叠/重复区间，跳过
                        continue
                    pieces.append(content[pos:start])
                    pieces.append(b"*:*:*:*:*:*:*:*")
                    pos = end
                pieces.append(content[pos:])
                content = b"".join(pieces)
        return content

    @staticmethod
    def _mask_sensitive_fields(content: bytes) -> bytes:
        """将日志中的敏感字段值隐藏，如 auth_token=123 → auth_token=xxxx，password=123 → password=xxxx。"""
        return _SENSITIVE_RE.sub(rb'\1xxxx', content)

    @classmethod
    def _mask_content(cls, content: bytes) -> bytes:
        """脱敏处理入口：根据内容特征精确跳过不需要的正则扫描。"""
        has_dot = b"." in content
        has_colon = b":" in content
        has_sensitive = (
            b"auth_token" in content or b"AUTH_TOKEN" in content
            or b"password" in content or b"PASSWORD" in content
        )
        if has_dot or has_colon:
            content = cls._mask_public_ips(content, has_dot=has_dot, has_colon=has_colon)
        if has_sensitive:
            content = cls._mask_sensitive_fields(content)
        return content

    def _try_copy(self, cmd: str, filepath: str) -> bool | None:
        """如果是简单 cat 命令，直接读文件，避免 shell/子进程和大输出一次性驻留内存。
        脱敏统一延后到子进程压缩阶段处理，这里只做原始拷贝。
        返回 True/False 表示是否成功处理；返回 None 表示应回退到 subprocess。"""
        if not cmd.startswith("cat ") or any(c in cmd for c in ("|", ">", "<", "&", ";")):
            return None
        src_path = cmd[4:].strip()
        src_paths = glob.glob(src_path) if any(c in src_path for c in ("*", "?", "[")) else [src_path]
        src_paths = [path for path in src_paths if os.path.isfile(path)]
        if not src_paths:
            return None

        try:
            with open(filepath, "wb") as f:
                for index, src_path in enumerate(src_paths):
                    if index:
                        f.write(b"\n\n")
                    with open(src_path, "rb") as src:
                        shutil.copyfileobj(src, f, length=_MASK_CHUNK_SIZE)
            return True
        except Exception as e:
            try:
                with open(filepath, "wb") as f:
                    f.write(f"Copy error: {str(e)}".encode())
            except Exception:
                pass
            return True

    def _write_command_output(self, filepath: str, stdout: bytes, stderr: bytes,
                              returncode: int) -> None:
        """写入命令原始输出（同步文件 IO，应在线程池中执行）。脱敏延后到压缩阶段。"""
        with open(filepath, "wb") as f:
            if stdout:
                f.write(stdout)
            if stderr:
                f.write(b"\n\n--- STDERR ---\n\n")
                f.write(stderr)

        # 如果命令失败且没有输出，创建错误标记
        if returncode != 0 and not stdout and not stderr:
            with open(filepath, "wb") as f:
                f.write(f"Command failed with exit code: {returncode}".encode())

    async def _execute_and_save(self, cmd: str, filepath: str) -> bool:
        """执行命令并保存原始结果（带故障处理）。脱敏统一在压缩阶段的子进程中完成。"""
        loop = asyncio.get_event_loop()

        # 简单 cat 命令直接拷贝，避免子进程开销；同步文件 IO 放到线程池
        handled = await loop.run_in_executor(None, self._try_copy, cmd, filepath)
        if handled is not None:
            return handled

        try:
            # 执行命令（子进程本身是真异步，等待输出不阻塞事件循环）
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            # 写文件（同步 IO）放到线程池
            await loop.run_in_executor(
                None, self._write_command_output,
                filepath, stdout, stderr, proc.returncode,
            )

            return True
        except Exception as e:
            # 执行异常，创建错误文件
            try:
                with open(filepath, "wb") as f:
                    f.write(f"Command execution error: {str(e)}".encode())
            except Exception:
                pass
            return False
    
    async def _save_frontend_log(self, request: web.Request, timestamp: str) -> str | None:
        """若请求携带 Body，则写入前端日志文件并返回路径；无 Body 时返回 None。

        流式读取并限制在 _FRONTEND_LOG_MAX_BYTES；超出则截断并追加标记。
        若 Content-Length 超过 aiohttp client_max_size，框架会直接返回 413。
        """
        if not request.can_read_body:
            return None

        # 流式读取到上限；超出部分丢弃并标记截断（Content-Length 超限由 aiohttp 先拒绝）
        chunks: list[bytes] = []
        written = 0
        truncated = False
        async for chunk in request.content.iter_chunked(64 * 1024):
            if truncated:
                continue  # 继续 drain，避免连接半开
            remain = _FRONTEND_LOG_MAX_BYTES - written
            if len(chunk) > remain:
                if remain > 0:
                    chunks.append(chunk[:remain])
                    written += remain
                truncated = True
                continue
            chunks.append(chunk)
            written += len(chunk)

        if written == 0:
            return None

        body = b"".join(chunks)
        if truncated:
            get_logger(0).warning(
                "Frontend log body truncated to %d bytes", _FRONTEND_LOG_MAX_BYTES
            )
            body += (
                b"\n\n--- TRUNCATED: frontend log exceeded "
                + str(_FRONTEND_LOG_MAX_BYTES).encode()
                + b" bytes ---\n"
            )

        filepath = f"{self.LOG_DIR}/frontend_{timestamp}.log"

        def _write() -> None:
            with open(filepath, "wb") as f:
                f.write(body)

        try:
            await asyncio.get_event_loop().run_in_executor(None, _write)
        except Exception as ex:
            get_logger(0).warning(f"Failed to write frontend log file: {ex}")
            return None

        get_logger(0).info(
            "Saved frontend log (%d bytes) to %s", written, filepath
        )
        return filepath

    async def collect_download_logs(self, request: web.Request, timestamp: str) -> web.StreamResponse:
        """收集日志并打包返回ZIP响应（主函数）"""
        loop = asyncio.get_event_loop()

        # 确保日志目录存在
        os.makedirs(self.LOG_DIR, exist_ok=True)

        # 可选：将请求 Body 作为前端日志一并打包
        frontend_log_path = await self._save_frontend_log(request, timestamp)
        
        # 构建命令字典（保持原代码逻辑）
        base_commands = self.config.get('base_commands', {})
        model_commands = self.config.get('model_commands', {}).get(self.__model, {})
        
        # 合并命令
        log_commands = {}
        for cmd, filename in base_commands.items():
            # 处理简单的字符串配置
            if isinstance(filename, dict):
                filename = filename.get('filename', 'unknown.log')
            log_commands[cmd] = f"{self.LOG_DIR}/{filename.replace('{timestamp}', timestamp)}"
        
        for cmd, filename in model_commands.items():
            if isinstance(filename, dict):
                filename = filename.get('filename', 'unknown.log')
            log_commands[cmd] = f"{self.LOG_DIR}/{filename.replace('{timestamp}', timestamp)}"
        
        # 收集日志（并行执行，用信号量限制并发数，避免资源争用）
        sem = asyncio.Semaphore(4)

        async def _collect_one(cmd: str, filepath: str) -> bool:
            async with sem:
                return await self._execute_and_save(cmd, filepath)

        tasks = [_collect_one(cmd, fpath) for cmd, fpath in log_commands.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

        # 脱敏 + DEFLATE 压缩都是 CPU 密集，且正则脱敏不释放 GIL，放到独立子进程执行，
        # 彻底绕开 GIL，避免阻塞主事件循环；子进程直接把 zip 落盘，避免内存翻倍。
        log_files = list(log_commands.values())
        if frontend_log_path:
            log_files.append(frontend_log_path)
        sensitive_patterns = self.config.get('sensitive_patterns', [])
        zip_path = f"{self.LOG_DIR}_{timestamp}.zip"
        try:
            with ProcessPoolExecutor(max_workers=1) as executor:
                await loop.run_in_executor(
                    executor, _subprocess_build_zip,
                    log_files, zip_path, sensitive_patterns,
                )
        except Exception as ex:
            # 子进程不可用时回退到线程池执行同一逻辑（压缩段释放 GIL，仍能缓解卡顿）
            get_logger(0).warning(f"ProcessPool zip build failed ({ex}), falling back to thread pool")
            await loop.run_in_executor(
                None, _subprocess_build_zip, log_files, zip_path, sensitive_patterns
            )

        # 准备响应并流式回传（读盘走线程池，发送 await，全程不阻塞事件循环）
        response = web.StreamResponse()
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename="system_logs_{timestamp}.zip"'
        response.content_length = os.path.getsize(zip_path)

        try:
            await response.prepare(request)
            with open(zip_path, "rb") as f:
                while True:
                    chunk = await loop.run_in_executor(None, f.read, 256 * 1024)
                    if not chunk:
                        break
                    await response.write(chunk)
            await response.write_eof()
        finally:
            # 清理日志目录和临时 zip，同步 IO 放到线程池
            await loop.run_in_executor(
                None, lambda: shutil.rmtree(self.LOG_DIR, ignore_errors=True)
            )
            try:
                os.remove(zip_path)
            except OSError:
                pass

        return response


def _subprocess_build_zip(log_files: list, zip_path: str, sensitive_patterns: list) -> None:
    """在独立子进程中完成脱敏 + 压缩并落盘，绕开 GIL，避免阻塞主事件循环。

    必须是模块级函数（可 pickle）才能交给 ProcessPoolExecutor 执行。
    流式读取每个日志文件：命中 sensitive_patterns 的分块脱敏后再压缩，避免大文件一次性进内存。
    """
    _READ_SIZE = 256 * 1024
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
            arcname = os.path.basename(log_file)
            need_mask = any(fnmatch.fnmatch(arcname, pat) for pat in sensitive_patterns)
            # 固定时间戳，规避 zip 对 <1980 时间戳报错；统一走流式写入控制内存
            info = zipfile.ZipInfo(arcname, date_time=(2025, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            try:
                with zf.open(info, "w") as dst, open(log_file, "rb") as src:
                    while True:
                        chunk = src.read(_READ_SIZE)
                        if not chunk:
                            break
                        if need_mask:
                            chunk = LogCollector._mask_content(chunk)
                        dst.write(chunk)
            except Exception as e:
                # 单个文件失败不影响整体打包
                try:
                    err_info = zipfile.ZipInfo(arcname + ".error", date_time=(2025, 1, 1, 0, 0, 0))
                    zf.writestr(err_info, f"Failed to pack {arcname}: {e}".encode())
                except Exception:
                    pass


class UpgradeApi:
    def __init__(self):
        self.__download_lock = asyncio.Lock()
        self.__current_download_task = None
        self.__total_firmware_size = 0
        
        # 读取model信息并更新URL
        try:
            with open(MODEL_PATH, "r") as f:
                model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm1: {str(e)}")
            model = "rm1"

        # 保存model信息
        self.__model = model

        # 更新URL
        self.__version_url = f"{BASE_URL.format(model=model)}/version"
        self.__firmware_url = f"{BASE_URL.format(model=model)}/update.img"
        self.__update_engine = UpdateEngine(BASE_URL.format(model=model))

    def __validate_edid(self, edid_str: str) -> bool:
        # 移除所有空白字符
        edid_str = ''.join(edid_str.split())
        
        # 检查长度（标准EDID是128字节或256字节，每个字节由2个十六进制字符表示）
        if len(edid_str) not in [256, 512]:
            return False
            
        # 检查是否都是有效的十六进制字符
        if not re.match(r'^[0-9A-Fa-f]+$', edid_str):
            return False
            
        return True
        
    def __convert_edid_to_bytes(self, edid_str: str) -> bytes:
        # 移除所有空白字符
        edid_str = ''.join(edid_str.split())
        
        # 如果EDID只有128字节(256个十六进制字符)，则追加指定的128字节
        if len(edid_str) == 256:
            # 追加的128字节数据
            additional_bytes = (
                "02 03 12 F0 23 09 04 01 83 01 00 00 65 03 0C 00 "
                "10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0"
            )
            # 移除空格
            additional_bytes = ''.join(additional_bytes.split())
            # 合并原始EDID和追加的数据
            edid_str = edid_str + additional_bytes
            get_logger(0).info("EDID is only 128 bytes, automatically appending additional 128 bytes")
            
        # 将十六进制字符串转换为字节
        return bytes.fromhex(edid_str)
    def __check_free_space(self, path: str, required_size: int) -> tuple[bool, str]:
        """检查指定路径所在分区的剩余空间是否足够
        
        Args:
            path: 要检查的路径
            required_size: 所需空间大小(字节)
            
        Returns:
            tuple[bool, str]: (是否有足够空间, 错误信息)
        """
        try:
            statvfs = os.statvfs(path)
            free_space = statvfs.f_frsize * statvfs.f_bavail
            if free_space < required_size:
                return False, f"Not enough space in {path}. Required: {required_size} bytes, Available: {free_space} bytes"
            return True, ""
        except Exception as e:
            return False, f"Failed to check free space: {str(e)}"

    @exposed_http("POST", "/upgrade/upload")
    async def __upload_handler(self, request: web.Request) -> web.Response:
        reader = await request.multipart()
        field = await reader.next()
        if field and field.name == "file":
            filename = field.filename
            # 树飞要求上传固件文件时，将__total_firmware_size设置为0
            self.__total_firmware_size = 0
            size = 0

            # 检查上传文件是否超过分区剩余空间
            content_length = request.headers.get('Content-Length')
            if content_length is None:
                return make_json_exception("Content-Length header is required", 400)
            content_length = int(content_length)
            get_logger(0).info("Content-Length: %s", content_length)
            has_space, error_msg = self.__check_free_space(UPGRADE_DIR, content_length)
            if not has_space:
                return make_json_exception(error_msg, 413)

            # ignore filename ,we only use update.img
            with open(f"{UPGRADE_DIR}{UPGRADE_FILE}", "wb") as f:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    size += len(chunk)
                    f.write(chunk)
            get_logger(0).info("Firmware file uploaded, size: %d bytes", size)
            return make_json_response({"filename": filename, "size": size})
        return web.HTTPBadRequest(text="No file uploaded")

    @exposed_http("GET", "/upgrade/compare")
    async def __compare_handler(self, request: web.Request) -> web.Response:
        result = await self.__update_engine.compare_versions()
        return make_json_response(result)

    @exposed_http(
        "GET",
        "/upgrade/gui_compare",
        allowed_exe_paths=["/usr/sbin/gl_kvm_gui"],
    )
    async def __gui_compare_handler(self, request: web.Request) -> web.Response:
        return await self.__compare_handler(request)
    
    @exposed_http("GET", "/upgrade/version")
    async def __version_handler(self, request: web.Request) -> web.Response:
        version = await self.__update_engine.get_local_verion()
        model = await self.__update_engine.get_local_model()
        return make_json_response({"version": version, "model": model})
    
    @exposed_http("GET", "/upgrade/reboot")
    async def __reboot_handler(self, request: web.Request) -> web.Response:
        asyncio.create_task(self.__delayed_reboot())
        return make_json_response({"status": "Reboot started"})

    @exposed_http("POST", "/upgrade/start")
    async def __start_handler(self, request: web.Request) -> web.Response:
        save_config = request.query.get("save_config")
        # 统一处理字符串和布尔值的情况
        save_config_value = str(save_config).lower() if save_config is not None else "true"
        should_save = save_config_value not in ["false", "0"]

        # 读取是否跳过签名验证的参数
        skip_verify = request.query.get("skip_verify")
        skip_verify_value = str(skip_verify).lower() if skip_verify is not None else "false"
        should_skip_verify = skip_verify_value in ["true", "1"]
        
        # 在升级前先校验固件
        if self.__model == "rmq1":
            pass
        else:
            signature_valid = True
            firmware_valid = True
            messages = []

            # 验证固件签名合法性（可通过 skip_verify 参数跳过）
            if should_skip_verify:
                get_logger(0).warning("Skipping firmware signature verification as requested")
            else:
                signature_result = await self.__update_engine.verify_firmware_signature()
                if signature_result["status"] != "valid":
                    signature_valid = False
                    messages.append(signature_result.get("message", "Firmware signature verification failed"))

            # 校验固件有效性
            validation_result = await self.__update_engine.validate_firmware()
            if validation_result["status"] != "valid":
                firmware_valid = False
                messages.append(validation_result.get("message", "Firmware validation failed"))

            # 任一校验失败则返回错误
            if not signature_valid or not firmware_valid:
                return make_json_response({
                    "status": "Upgrade failed",
                    "signature_valid": signature_valid,
                    "firmware_valid": firmware_valid,
                    "message": "; ".join(messages),
                    "stdout": validation_result.get("stdout", ""),
                    "stderr": validation_result.get("stderr", ""),
                })
        
        result = await self.__update_engine.start_upgrade(save_config=should_save)
        if result.get("status") == "Upgrade started":
            asyncio.create_task(self.__delayed_reboot())
        return make_json_response(result)

    async def __delayed_reboot(self):
        await asyncio.create_subprocess_shell("sync")
        await asyncio.sleep(1)
        await asyncio.create_subprocess_shell("reboot")

    @exposed_http("GET", "/upgrade/status")
    async def __status_handler(self, request: web.Request) -> web.Response:
        return make_json_response({"enabled": True})

    @exposed_http("GET", "/upgrade/reset_default")
    async def __reset_default_handler(self, request: web.Request) -> web.Response:
        # 创建异步任务运行恢复出厂设置命令
        asyncio.create_task(self.__delayed_reset_default())
        return make_json_response({"status": "Reset to factory default started"})
        
    async def __delayed_reset_default(self):
        # 先同步数据到磁盘
        await asyncio.create_subprocess_shell("sync")
        await asyncio.sleep(1)
        # 执行恢复出厂设置命令
        await asyncio.create_subprocess_shell("/usr/sbin/reset_default.sh")

    @exposed_http("GET", "/upgrade/download")
    async def __download_handler(self, request: web.Request) -> web.Response:
        return await self.__start_download_task(
            base_url=self.__update_engine.get_base_url(),
        )

    @exposed_http("GET", "/upgrade/beta/download")
    async def __beta_download_handler(self, request: web.Request) -> web.Response:
        return await self.__start_download_task(
            base_url=self.__update_engine.get_beta_base_url(),
            list_sha256_url=self.__update_engine.get_beta_list_sha256_url(),
        )

    async def __start_download_task(self, base_url: str,
                                     list_sha256_url: str = None) -> web.Response:
        # 如果有正在进行的下载任务，取消它
        if self.__current_download_task and not self.__current_download_task.done():
            self.__current_download_task.cancel()
            try:
                await self.__current_download_task
            except asyncio.CancelledError:
                pass

        # 创建新的下载任务。started 只承载"已取得固件大小"这一步的结果：
        # 本请求拿到 size 就返回，剩下的下载在后台任务里继续，避免整个下载期间
        # 一直占住这条 HTTP 连接（会导致后续 /api 请求被 nginx 卡住直到下载结束）
        started: asyncio.Future = asyncio.get_event_loop().create_future()
        self.__current_download_task = asyncio.create_task(
            self._download_latest_firmware(base_url, list_sha256_url, started)
        )
        size = await started
        return make_json_response({"size": size})

    @exposed_http("GET", "/upgrade/download_cancel")
    async def __download_cancel_handler(self, request: web.Request) -> web.Response:
        self.__total_firmware_size = 0
        if self.__current_download_task and not self.__current_download_task.done():
            # 取消当前下载任务
            self.__current_download_task.cancel()
            try:
                await self.__current_download_task
            except asyncio.CancelledError:
                pass
            get_logger(0).info("Firmware download task has been manually cancelled")
            return make_json_response({"status": "success", "message": "download task has been cancelled"})
        else:
            return make_json_response({"status": "warning", "message": "no download task is running"})

    @exposed_http("GET", "/upgrade/download_info")
    async def __download_info_handler(self, request: web.Request) -> web.Response:
        # 获取当前固件大小
        try:
            size = os.path.getsize(f"{UPGRADE_DIR}{UPGRADE_FILE}")
        except Exception as ex:
            return make_json_response({"size": 0, "total_size": 0})
        return make_json_response({"size": size, "total_size": self.__total_firmware_size})

    @exposed_http("POST", "/upgrade/edid")
    async def __edid_handler(self, request: web.Request) -> web.Response:
        try:
            # 读取请求体中的edid参数
            data = await request.post()
            edid_str = data.get("edid", "")

            # 验证EDID数据
            if not self.__validate_edid(edid_str):
                raise BadRequestError("Invalid EDID format")
                
            # 转换为字节数据
            edid_bytes = self.__convert_edid_to_bytes(edid_str)
            
            # 写入临时文件
            with open(EDID_FILE, "wb") as f:
                f.write(edid_bytes)
            
            # 保存原始edid字符串到用户配置文件
            os.makedirs(os.path.dirname(EDID_USER_FILE), exist_ok=True)
            with open(EDID_USER_FILE, "w") as f:
                f.write(edid_str)
            await asyncio.create_subprocess_shell("sync")
            
            cmd_map = {
                "rm10rc": GSV1127X_UPGRADE_CMD,
                "rm4pe": GSV1127X_UPGRADE_CMD,
                "rmq1": GSV1127_UPGRADE_CMD,
            }

            edid_cmd = cmd_map.get(self.__model, LT6911C_UPGRADE_CMD)
            # get_logger(0).info(f"Using command: {edid_cmd}")

            # 执行x_upgrade命令
            proc = await asyncio.create_subprocess_shell(
                edid_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                raise BadRequestError(f"Failed to execute x_upgrade: {stderr.decode()}")
                
            return make_json_response({
                "status": "success",
                "message": "EDID data has been written and applied"
            })
            
        except BadRequestError as ex:
            return make_json_exception(ex, 400)
        except Exception as ex:
            return make_json_exception(str(ex), 500)

    @exposed_http("GET", "/upgrade/get_edid")
    async def __get_edid_handler(self, request: web.Request) -> web.Response:
        try:
            if not os.path.exists(EDID_USER_FILE):
                # 如果文件不存在，返回空字符串
                return make_json_response({"edid": ""})
                
            # 读取保存的EDID数据
            with open(EDID_USER_FILE, "r") as f:
                edid_str = f.read().strip()
                
            return make_json_response({"edid": edid_str})
            
        except Exception as ex:
            get_logger(0).error(f"Error getting EDID data: {str(ex)}")
            return make_json_exception(str(ex), 500)

    @exposed_http("GET", "/upgrade/edid_list")
    async def __get_edid_list_handler(self, _: web.Request) -> web.Response:
        try:
            with open(EDID_LIST_FILE, "r", encoding="utf-8") as f:
                data = f.read()
        except FileNotFoundError:
            get_logger(0).warning("edid.json not found at %s", EDID_LIST_FILE)
            data = "[]"
        except Exception as ex:
            get_logger(0).error(f"Error reading edid.json: {ex}")
            data = "[]"
        return web.Response(text=data, content_type="application/json")

    @exposed_http("GET", "/upgrade/log")
    async def __log_get_handler(self, request: web.Request) -> web.Response:
        return await self.__log_handler(request)

    @exposed_http("POST", "/upgrade/log")
    async def __log_post_handler(self, request: web.Request) -> web.Response:
        return await self.__log_handler(request)

    async def __log_handler(self, request: web.Request) -> web.Response:
        try:
            # 创建临时日志目录
            os.makedirs(LOG_DIR, exist_ok=True)
            
            # 获取当前时间戳作为文件名前缀
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            collector = LogCollector(
                model=self.__model,
                log_dir=f"{LOG_DIR}",
                config_path="/etc/kvmd/log_config.yaml"
            )

            return await collector.collect_download_logs(request, timestamp)
            
        except Exception as ex:
            get_logger(0).error(f"Error collecting logs: {str(ex)}")
            return make_json_exception(f"Error collecting logs: {str(ex)}", 500)

    async def _download_latest_firmware(self, base_url: str, list_sha256_url: str,
                                         started: asyncio.Future) -> None:
        written = 0

        async with self.__download_lock:
            try:
                # 使用get_list_sha256方法获取固件文件名
                version, firmware_filename = await self.__update_engine.get_list_sha256(list_sha256_url)
                if not firmware_filename:
                    raise BadRequestError("Unable to get firmware filename")

                # 构建完整的固件下载URL
                firmware_url = f"{base_url}/{firmware_filename}"
                get_logger(0).info("Generated firmware URL: %s", firmware_url)

                async with htclient.download(
                    url=firmware_url,
                    timeout=10.0,
                    read_timeout=(7 * 24 * 3600),  # 7天超时
                ) as remote:
                    size = remote.content_length
                    if not size:
                        raise BadRequestError("Unable to get firmware size")

                    # 立即把文件大小交回请求方，请求到此就结束了
                    self.__total_firmware_size = size
                    if not started.done():
                        started.set_result(size)

                    get_logger(0).info("Downloading firmware from %r to %r ...", firmware_url, f"{UPGRADE_DIR}{UPGRADE_FILE}")

                    # 分块下载并写入文件
                    chunk_size = 8192
                    with open(f"{UPGRADE_DIR}{UPGRADE_FILE}", "wb") as f:
                        try:
                            async for chunk in remote.content.iter_chunked(chunk_size):
                                f.write(chunk)
                                written += len(chunk)
                        except asyncio.CancelledError:
                            get_logger(0).info("Download task cancelled")
                            raise
                    get_logger(0).info("Firmware downloaded, %d bytes written", written)

            except asyncio.CancelledError:
                # 还没上报 size 就被取消，让等待中的请求收到 400 而不是一直挂着
                if not started.done():
                    started.set_exception(BadRequestError("Download task was cancelled"))
                raise
            except Exception as ex:
                get_logger(0).error("Error downloading firmware: %s", str(ex))
                if not started.done():
                    started.set_exception(ex if isinstance(ex, BadRequestError) else BadRequestError(str(ex)))
                # size 已上报时请求早已返回，这里只记日志，避免后台任务异常无人接收

class UpdateEngine:
    def __init__(self,base_url: str):
        self.__base_url = base_url
        self.__version_url = base_url+"/version"
        self.__firmware_url = base_url+"/update.img"
        self.__list_sha256_url = base_url+"/list-sha256.txt"

        try:
            with open(MODEL_PATH, "r") as f:
                model = f.read().strip()
        except Exception as e:
            get_logger(0).warning(f"Failed to read model info, using default value rm1: {str(e)}")
            model = "rm1"

        # 保存model信息
        self.__model = model

        # Beta渠道URL
        self.__beta_base_url = BETA_BASE_URL.format(model=model)
        self.__beta_list_sha256_url = f"{self.__beta_base_url}/list-sha256.txt"

    async def get_local_verion(self):
        with open("/etc/version", "r") as f:
            local_content = f.read().strip()
        local_dict = dict(line.split('=') for line in local_content.splitlines())
        return local_dict.get('RK_VERSION', '')

    async def get_local_model(self):
        with open("/etc/version", "r") as f:
            local_content = f.read().strip()
        local_dict = dict(line.split('=') for line in local_content.splitlines())
        return local_dict.get('RK_MODEL', '')

    async def get_list_sha256(self, list_sha256_url: str = None) -> tuple[str, str]:
        url = list_sha256_url or self.__list_sha256_url
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        first_line = content.splitlines()[0]
                        version = first_line.split()[0]  # 获取第一个字段作为版本号
                        firmware = first_line.split()[1]  # 获取第二个字段作为固件类型
                        return version, firmware
                    else:
                        get_logger(0).error(f"Failed to get list-sha256 from {url}: {response.status}")
                        return "", ""
        except asyncio.CancelledError:
            get_logger(0).warning("List-sha256 request was cancelled")
            return "", ""
        except Exception as e:
            get_logger(0).error(f"Error getting list-sha256: {str(e)}")
            return "", ""
    
    def get_base_url(self) -> str:
        return self.__base_url

    def get_beta_base_url(self) -> str:
        return self.__beta_base_url

    def get_beta_list_sha256_url(self) -> str:
        return self.__beta_list_sha256_url

    async def __get_metadata(self, version: str, base_url: str = None) -> Dict[str, Any]:
        """获取指定版本的metadata信息"""
        try:
            if base_url is None:
                base_url = self.__base_url
            metadata_url = f"{base_url}/metadata_{version}"
            async with aiohttp.ClientSession() as session:
                async with session.get(metadata_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        metadata = json.loads(text)
                        return metadata
                    else:
                        get_logger(0).error(f"Failed to get metadata: {response.status}")
                        return {}
        except asyncio.CancelledError:
            # 处理请求被取消的情况
            get_logger(0).warning("Metadata request was cancelled")
            return {}
        except Exception as e:
            get_logger(0).error(f"Error getting metadata: {str(e)}")
            return {}

    async def __fetch_channel_version(self, list_sha256_url: str, base_url: str, channel: str) -> Dict[str, Any]:
        """获取指定渠道的版本信息
        
        Args:
            list_sha256_url: list-sha256.txt 的完整URL
            base_url: 渠道的base URL，用于获取metadata
            channel: 渠道名称，用于日志
            
        Returns:
            Dict: 包含 version, release_note, release_note_cn, error 字段
        """
        info: Dict[str, Any] = {"version": "", "release_note": "", "release_note_cn": "", "error": None}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(list_sha256_url) as response:
                    if response.status != 200:
                        info["error"] = f"{channel} channel returned status code: {response.status}"
                        return info
                    list_content = await response.text()
                    lines = list_content.strip().splitlines()
                    if not lines:
                        info["error"] = f"Empty {channel} list-sha256 response"
                        return info
                    parts = lines[0].split()
                    if not parts:
                        info["error"] = f"Invalid {channel} list-sha256 format"
                        return info
                    version = parts[0]
                    metadata = await self.__get_metadata(version, base_url)
                    if metadata and "version" in metadata:
                        version_info = metadata["version"]
                        info["version"] = f"V{version_info['release']} {version_info['firmware_type']}"
                        info["release_note"] = metadata.get("release_note", "")
                        info["release_note_cn"] = metadata.get("release_note_cn", "")
                    else:
                        info["error"] = f"Unable to get {channel} version information from metadata"
        except asyncio.CancelledError:
            info["error"] = f"{channel} request was cancelled"
            get_logger(0).warning(f"{channel} version request was cancelled")
        except Exception as e:
            info["error"] = f"Failed to fetch {channel} version: {str(e)}"
        return info

    async def compare_versions(self) -> Dict[str, Any]:
        # 初始化返回结果
        result = {
            "local_model": "",
            "local_version": "",
            "server_model": "",
            "server_version": "",
            "beta_version": "",
            "beta_release_note": "",
            "beta_release_note_cn": "",
            "beta_error": None,
            "error": None
        }

        # 读取本地版本
        try:
            with open("/etc/version", "r") as f:
                local_content = f.read().strip()
            local_dict = dict(line.split('=') for line in local_content.splitlines())
            result["local_model"] = local_dict.get('RK_MODEL', '')
            result["local_version"] = local_dict.get('RK_VERSION', '')
        except Exception as e:
            result["error"] = f"Failed to read local version: {str(e)}"
            return result

        # 并发获取 Release 和 Beta 渠道版本信息
        release_task = self.__fetch_channel_version(self.__list_sha256_url, self.__base_url, "Release")
        beta_task = self.__fetch_channel_version(self.__beta_list_sha256_url, self.__beta_base_url, "Beta")
        release_info, beta_info = await asyncio.gather(release_task, beta_task)

        # 填充 Release 信息
        if release_info["error"]:
            result["error"] = release_info["error"]
        else:
            result["server_model"] = result["local_model"]
            result["server_version"] = release_info["version"]
            result["release_note"] = release_info["release_note"]
            result["release_note_cn"] = release_info["release_note_cn"]

        # 填充 Beta 信息
        if beta_info["error"]:
            result["beta_error"] = beta_info["error"]
        else:
            result["beta_version"] = beta_info["version"]
            result["beta_release_note"] = beta_info["release_note"]
            result["beta_release_note_cn"] = beta_info["release_note_cn"]

        return result

    async def start_upgrade(self,save_config: bool=True) -> Dict[str, str]:
        if self.__model == "rmq1":
            cmd = f"swupdate_start.sh -i /userdata/update.img" + (" -K" if save_config else "")
        else:
            save_config_cmd = " --keep_config" if save_config else ""
            cmd = f"updateEngine --image_url={UPGRADE_DIR}{UPGRADE_FILE} --misc=update --savepath=/userdata/update.img --n {save_config_cmd}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return {"status": "Upgrade started", "stdout": stdout.decode(), "stderr": stderr.decode()}
        else:
            return {"status": "Upgrade failed", "stdout": stdout.decode(), "stderr": stderr.decode()}

    async def verify_firmware_signature(self) -> Dict[str, Any]:
        """
        验证固件文件的签名合法性
        使用 fwtools verify 命令校验 /userdata/update.img 的签名
        
        Returns:
            Dict[str, Any]: 包含验证结果的字典
                - status: "valid" 或 "invalid" 或 "error"
                - message: 详细信息
                - stdout: 命令输出
                - stderr: 错误输出
        """
        try:
            firmware_path = f"{UPGRADE_DIR}{UPGRADE_FILE}"
            if not os.path.exists(firmware_path):
                return {
                    "status": "error",
                    "message": "Firmware file does not exist",
                    "stdout": "",
                    "stderr": ""
                }
            
            public_key_path = "/etc/firmware/key/public.raw"
            if not os.path.exists(public_key_path):
                return {
                    "status": "error",
                    "message": "Public key file does not exist",
                    "stdout": "",
                    "stderr": ""
                }
            
            cmd = f"fwtools verify {firmware_path} {public_key_path}"
            get_logger(0).info(f"Verifying firmware signature: {cmd}")
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            stdout_str = stdout.decode().strip()
            stderr_str = stderr.decode().strip()
            
            if proc.returncode == 0:
                get_logger(0).info("Firmware signature verification successful")
                return {
                    "status": "valid",
                    "message": "Firmware signature verification successful",
                    "stdout": stdout_str,
                    "stderr": stderr_str
                }
            else:
                get_logger(0).error(f"Firmware signature verification failed: {stderr_str}")
                return {
                    "status": "invalid",
                    "message": "Firmware signature verification failed",
                    "stdout": stdout_str,
                    "stderr": stderr_str
                }
                
        except Exception as e:
            get_logger(0).error(f"Error verifying firmware signature: {str(e)}")
            return {
                "status": "error",
                "message": f"Error during firmware signature verification: {str(e)}",
                "stdout": "",
                "stderr": ""
            }

    async def validate_firmware(self) -> Dict[str, Any]:
        """
        校验固件文件的有效性
        使用 check_image_validity 命令校验 /userdata/update.img 文件
        
        Returns:
            Dict[str, Any]: 包含校验结果的字典
                - status: "valid" 或 "invalid" 或 "error"
                - message: 详细信息
                - stdout: 命令输出
                - stderr: 错误输出
        """
        try:
            # 首先检查固件文件是否存在
            firmware_path = f"{UPGRADE_DIR}{UPGRADE_FILE}"
            if not os.path.exists(firmware_path):
                return {
                    "status": "error",
                    "message": "Firmware file does not exist",
                    "stdout": "",
                    "stderr": ""
                }
            
            # 执行校验命令
            cmd = f"check_image_validity {firmware_path}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            stdout_str = stdout.decode().strip()
            stderr_str = stderr.decode().strip()
            
            if proc.returncode == 0:
                return {
                    "status": "valid",
                    "message": "Firmware validation successful",
                    "stdout": stdout_str,
                    "stderr": stderr_str
                }
            else:
                return {
                    "status": "invalid",
                    "message": "Firmware validation failed",
                    "stdout": stdout_str,
                    "stderr": stderr_str
                }
                
        except Exception as e:
            get_logger(0).error(f"Error validating firmware: {str(e)}")
            return {
                "status": "error",
                "message": f"Error during firmware validation: {str(e)}",
                "stdout": "",
                "stderr": ""
            }
