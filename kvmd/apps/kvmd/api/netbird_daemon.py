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

"""
直连 netbird daemon 的 unix socket 读状态，替代 fork `netbird status --json`。

netbird daemon 由 S99netbird 以 `--daemon-addr unix:///var/run/netbird.sock` 拉起，
socket 上跑的是 gRPC（不像 tailscaled 的 LocalAPI 是 JSON over HTTP），所以这里用
grpc.aio 直接发 `DaemonService/Status`。RV1126 实测：CLI 约 118ms，走 socket 热调用
约 4ms。

只需要响应里的 4 个字段，所以不引入生成的 pb2 代码，直接收发 bytes 并用下面的最小
protobuf 读取器取字段 —— netbird 升版本时不需要重新 codegen（proto3 的字段号是兼容
性契约）。
"""

import asyncio
import os

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ....logging import get_logger


# ===== gRPC 端点 =====

_SOCK_PATH = "/var/run/netbird.sock"
_TARGET = f"unix://{_SOCK_PATH}"
_METHOD = "/daemon.DaemonService/Status"
_TIMEOUT = 5.0

# StatusRequest{getFullPeerStatus: true, shouldRunProbes: false} 的序列化结果。
# 必须置 getFullPeerStatus，daemon 只有在该分支里才会填充 FullStatus
# （netbird client/server/server.go 的 Server.Status）；shouldRunProbes 保持 false，
# 与 CLI 的 `netbird status --json` 一致，不触发对端探测。
_STATUS_REQUEST = b"\x08\x01"


# ===== protobuf 字段号，来自 netbird v0.74.7 的 client/proto/daemon.proto =====

_STATUS_RESPONSE_STATUS = 1          # string
_STATUS_RESPONSE_FULL_STATUS = 2     # FullStatus
_STATUS_RESPONSE_DAEMON_VERSION = 3  # string

_FULL_STATUS_MANAGEMENT_STATE = 1  # ManagementState
_FULL_STATUS_LOCAL_PEER_STATE = 3  # LocalPeerState

_MANAGEMENT_STATE_CONNECTED = 2  # bool

_LOCAL_PEER_STATE_IP = 1  # string

# StatusResponse.status 的取值，见 netbird client/internal/state.go
LOGGED_OUT_STATUSES = frozenset(["NeedsLogin", "LoginFailed", "SessionExpired"])


class NetbirdDaemonUnavailableError(Exception):
    """
    连不上 daemon 的 socket。除了服务没起来，还有两种常见情况：daemon 正在退出（socket
    已删、进程还在 /proc 里），以及 stop 之后只剩下 _get_login_url 拉起的 `netbird up`
    残留进程 —— 这两种都不算服务异常，调用方应当当作"没在跑"处理。
    """


@dataclass(frozen=True)
class NetbirdStatus:
    status: str          # Idle / Connecting / Connected / NeedsLogin / LoginFailed / SessionExpired
    connected: bool      # 是否连上 management server
    ip: str              # netbird 分配的地址，带掩码（形如 100.x.y.z/16），未登录时为空
    daemon_version: str

    @property
    def logged_out(self) -> bool:
        return self.status in LOGGED_OUT_STATUSES


# ===== 最小 protobuf 读取器 =====

def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("Truncated protobuf varint")
        if shift > 63:
            raise ValueError("Protobuf varint is too long")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return (value, pos)
        shift += 7


def read_fields(buf: bytes) -> Dict[int, Any]:
    """
    把一层 protobuf message 解成 {字段号: 值}。varint 解成 int，length-delimited 解成
    bytes（字符串/嵌套 message 都走这条），定长的 32/64 位字段直接跳过 —— 我们要的字段
    都不是这两种。同一字段号重复出现时后者覆盖前者，与 proto3 对非 repeated 字段的规定
    一致。
    """
    fields: Dict[int, Any] = {}
    pos = 0
    while pos < len(buf):
        (key, pos) = _read_varint(buf, pos)
        (number, wire_type) = (key >> 3, key & 0x07)
        if wire_type == 0:  # varint
            (fields[number], pos) = _read_varint(buf, pos)
        elif wire_type == 2:  # length-delimited
            (length, pos) = _read_varint(buf, pos)
            end = pos + length
            if end > len(buf):
                raise ValueError("Truncated protobuf length-delimited field")
            fields[number] = buf[pos:end]
            pos = end
        elif wire_type == 5:  # 32-bit
            pos += 4
        elif wire_type == 1:  # 64-bit
            pos += 8
        else:
            # 3/4 是已废弃的 group，daemon.proto 里不会出现
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")
        if pos > len(buf):
            raise ValueError("Truncated protobuf message")
    return fields


def _sub_message(fields: Dict[int, Any], number: int) -> Dict[int, Any]:
    raw = fields.get(number)
    return (read_fields(raw) if isinstance(raw, bytes) else {})


def _string(fields: Dict[int, Any], number: int) -> str:
    raw = fields.get(number)
    return (raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else "")


def parse_status_response(raw: bytes) -> NetbirdStatus:
    response = read_fields(raw)
    full_status = _sub_message(response, _STATUS_RESPONSE_FULL_STATUS)
    management = _sub_message(full_status, _FULL_STATUS_MANAGEMENT_STATE)
    local_peer = _sub_message(full_status, _FULL_STATUS_LOCAL_PEER_STATE)
    return NetbirdStatus(
        status=_string(response, _STATUS_RESPONSE_STATUS),
        connected=bool(management.get(_MANAGEMENT_STATE_CONNECTED, 0)),
        ip=_string(local_peer, _LOCAL_PEER_STATE_IP),
        daemon_version=_string(response, _STATUS_RESPONSE_DAEMON_VERSION),
    )


# ===== 客户端 =====

def _is_unavailable(ex: BaseException) -> bool:
    # 不在这里 import grpc（模块顶层没有它），靠 AioRpcError 的 code() 鸭子类型判断
    code = getattr(ex, "code", None)
    if not callable(code):
        return False
    try:
        return (getattr(code(), "name", "") == "UNAVAILABLE")
    except Exception:
        return False


class NetbirdDaemonClient:
    """
    复用同一个 channel 的 Status 客户端。建 channel 在 RV1126 上要 ~93ms，所以只建一次；
    daemon 被重启（S99netbird stop/start）后调用方应该 close()，让下次请求重新 dial。
    """

    def __init__(self, logger: Any = None) -> None:
        self.__logger = (logger or get_logger(0))
        self.__lock = asyncio.Lock()
        self.__channel: Optional[Any] = None
        self.__call: Optional[Any] = None

    async def get_status(self, timeout: float = _TIMEOUT) -> NetbirdStatus:
        """
        grpcio 不可用时抛 ImportError，daemon 连不上时抛 NetbirdDaemonUnavailableError，
        其它 gRPC 错误按原样抛出。
        """
        if not os.path.exists(_SOCK_PATH):
            # 提前挡掉，省下 grpc 的 import 和 dial —— 服务没起来时这是最常走的分支
            raise NetbirdDaemonUnavailableError(f"No such socket: {_SOCK_PATH}")
        call = await self.__ensure_call()
        try:
            raw = await call(_STATUS_REQUEST, timeout=timeout)
        except Exception as ex:
            if _is_unavailable(ex):
                raise NetbirdDaemonUnavailableError(str(ex)) from ex
            raise
        return parse_status_response(raw)

    async def __ensure_call(self) -> Any:
        async with self.__lock:
            if self.__call is None:
                # 惰性导入：`import grpc` 在 RV1126 上要 ~880ms，不能拖慢 kvmd 启动；
                # 同时 rootfs 万一裁掉了 grpcio，调用方还能退回 CLI。
                import grpc
                self.__channel = grpc.aio.insecure_channel(_TARGET)
                self.__call = self.__channel.unary_unary(
                    _METHOD,
                    request_serializer=(lambda raw: raw),
                    response_deserializer=(lambda raw: raw),
                )
            return self.__call

    async def close(self) -> None:
        async with self.__lock:
            channel = self.__channel
            self.__channel = None
            self.__call = None
        if channel is not None:
            try:
                await channel.close()
            except Exception as ex:
                self.__logger.warning("Error closing netbird daemon channel: %s", ex)
