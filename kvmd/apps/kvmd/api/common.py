# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #

import asyncio
import json
import os
import re
import subprocess
from typing import Any, Iterable, Mapping, Optional, Sequence

from ....htserver import BadRequestError
from ....logging import get_logger
from ....tools import run_shell


# 哨兵对象：用于区分"未指定 error_status"与"显式传入某个值（含空字符串）"
_ERROR_STATUS_UNSET = object()

# MAC 地址校验正则，防止命令注入
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _make_command_error(error_status: object, fallback: str) -> BadRequestError:
    if error_status is _ERROR_STATUS_UNSET:
        return BadRequestError(fallback)
    return BadRequestError(error_status)


async def run_process(
    cmd: Sequence[str],
    *,
    logger=None,
    timeout: Optional[float] = None,
    error_status: object = _ERROR_STATUS_UNSET,
) -> str:
    logger = logger or get_logger(0)
    process: Optional[asyncio.subprocess.Process] = None
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        communicate = process.communicate()
        if timeout is not None:
            stdout, stderr = await asyncio.wait_for(communicate, timeout=timeout)
        else:
            stdout, stderr = await communicate
        stdout_str = stdout.decode().strip()
        stderr_str = stderr.decode().strip()
        if process.returncode != 0:
            logger.error("Command failed: %s", stderr_str)
            raise _make_command_error(error_status, stderr_str)
        return stdout_str
    except asyncio.TimeoutError:
        logger.warning("Command timed out after %ss: %r", timeout, list(cmd))
        if process is not None and process.returncode is None:
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass
        raise _make_command_error(error_status, f"Command timed out after {timeout}s")
    except BadRequestError:
        raise
    except Exception as ex:
        logger.error("Error executing command %r: %s", list(cmd), ex)
        raise _make_command_error(error_status, f"Error executing command: {ex}")


async def run_command(
    cmd: str,
    *,
    logger=None,
    timeout: Optional[float] = None,
    error_status: object = _ERROR_STATUS_UNSET,
) -> str:
    return await run_process(cmd.split(), logger=logger, timeout=timeout, error_status=error_status)


async def is_process_running(cmd: Sequence[str], *, logger=None, error_label: str = "process") -> bool:
    logger = logger or get_logger(0)
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        await process.communicate()
        return process.returncode == 0
    except Exception as ex:
        logger.error("Error checking %s: %s", error_label, ex)
        return False


def is_process_running_by_name(
    name: str,
    *,
    pid_path: Optional[str] = None,
    scan_fallback: bool = True,
    logger=None,
) -> bool:
    """
    通过 /proc 判断进程是否存活，避免 fork pidof/pgrep。

    给了 pid_path（daemon 由 start-stop-daemon 之类管理、有可信 pidfile）时以 pidfile 为准：
    读出 pid 再用 /proc/<pid>/comm 校验，只读两个文件。init 脚本停服后往往会残留 pidfile，
    comm 校验能识别出来（进程已消失或 pid 被复用），因此残留不会误判成 running。
    只有 pidfile 缺失或内容非法时才退回扫描整个 /proc —— 该路径在 RV1126 上要 ~45ms，
    比 fork 一个 pidof 还慢，不能当常规兜底用。

    init 脚本在 stop 时会删掉 pidfile（此时"没有 pidfile"就等价于"没在跑"），把
    scan_fallback 置 False 可以跳过这次全扫描，让停服状态下的查询也是常数开销。

    注意 comm 会被内核截断到 15 个字符，name 超过该长度时匹配不到。
    """
    logger = logger or get_logger(0)
    if pid_path is not None:
        try:
            with open(pid_path, "r") as file:
                pid = file.read().strip()
            if pid.isdigit():
                return _read_proc_comm(pid) == name
        except OSError:
            pass  # pidfile 不存在或不可读，退回扫描
        except Exception as ex:
            logger.error("Error reading pidfile %s: %s", pid_path, ex)
        if not scan_fallback:
            return False
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit() and _read_proc_comm(pid) == name:
                return True
        return False
    except Exception as ex:
        logger.error("Error scanning /proc for %s: %s", name, ex)
        return False


def _read_proc_comm(pid: str) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/comm", "r") as file:
            return file.read().strip()
    except OSError:
        # 进程可能刚刚退出，或者 /proc/<pid> 不可读
        return None


async def read_json_file(
    path: str,
    default: Mapping[str, Any],
    *,
    logger=None,
) -> dict[str, Any]:
    logger = logger or get_logger(0)
    data = dict(default)
    try:
        if os.path.exists(path):
            with open(path, "r") as file:
                loaded = json.load(file)
            if isinstance(loaded, dict):
                data.update(loaded)
        return data
    except Exception as ex:
        logger.error("Failed to read config file %s: %s", path, ex)
        return data


async def write_json_file(path: str, data: Mapping[str, Any], *, logger=None, sync: bool = True) -> None:
    logger = logger or get_logger(0)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as file:
            json.dump(dict(data), file, indent=4)
        if sync:
            await run_shell("sync")
    except Exception as ex:
        logger.error("Failed to write config file %s: %s", path, ex)
        raise BadRequestError(f"Failed to write config file: {ex}")


async def update_json_file(
    path: str,
    default: Mapping[str, Any],
    updates: Mapping[str, Any],
    *,
    logger=None,
) -> dict[str, Any]:
    config = await read_json_file(path, default, logger=logger)
    for key, value in updates.items():
        if value is not None:
            config[key] = value
    await write_json_file(path, config, logger=logger)
    return config


def valid_mac(mac: str) -> str:
    mac = mac.strip()
    if not _MAC_RE.match(mac):
        raise BadRequestError("Invalid MAC address format")
    return mac


def make_device_name_from_mac(mac: str) -> str:
    return f"device-{mac.replace(':', '').replace('-', '')[-4:]}"


def first_url_from_lines(lines: Iterable[str], scheme: str = "https://") -> Optional[str]:
    for line in lines:
        if scheme in line:
            for word in line.split():
                if word.startswith(scheme):
                    return word
            return line
    return None