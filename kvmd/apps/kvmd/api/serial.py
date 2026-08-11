"""
串口设备 WebSocket 桥接 API
提供两个接口：
  GET /api/serial/list  -- 列出可用串口设备
  GET /api/serial/ws    -- WebSocket → 串口 直连桥 (方案二：直接操作串口 fd，无 PTY)

WebSocket 协议:
  - 收到 binary frame  → 写入串口
  - 收到 text frame    → utf-8 编码后写入串口
  - 串口数据           → 发送 binary frame 到前端
"""

import os
import glob
import asyncio
import termios
import struct
import fcntl
import ctypes
import ctypes.util
import array

from typing import AsyncGenerator, Optional

from aiohttp.web import Request, Response, WebSocketResponse, WSMsgType

from ....htserver import exposed_http, make_json_response, make_json_exception, BadRequestError
from ....logging import get_logger

_logger = get_logger()

# ── termios2 / BOTHER 常量（用于设置任意波特率）────────────────────────────
# BOTHER 和 CBAUD 在所有 Linux 架构上相同
BOTHER  = 0o010000
CBAUD   = 0o010017

# TCGETS2/TCSETS2 的 ioctl number 根据架构不同：
# 使用 _IOR/_IOW 宏计算: _IOR('T', 0x2A, struct termios2) / _IOW('T', 0x2B, struct termios2)
# struct termios2 大小 = 44 字节
import platform as _platform
_TERMIOS2_SIZE = 44
_arch = _platform.machine()
if _arch in ('aarch64', 'armv7l', 'arm'):
    # ARM: direction bits 在高位, _IOC(dir, type, nr, size)
    #   _IOC_READ=2, _IOC_WRITE=1 (ARM 相反于 x86!)
    #   但实际上 ARM 和 x86 的 TCGETS2/TCSETS2 数值相同，因为 'T' serial ioctl
    #   使用的是旧式 ioctl 编号（不带 direction/size 编码）
    # 在 ARM Linux 中: TCGETS2=0x802C542A, TCSETS2=0x402C542B
    TCGETS2 = 0x802C542A
    TCSETS2  = 0x402C542B
else:
    # x86/x86_64: 同样的值
    TCGETS2 = 0x802C542A
    TCSETS2  = 0x402C542B

# ── termios 标准波特率常量映射（作为 fallback）─────────────────────────────
_BAUD_MAP = {
    50:      termios.B50,
    75:      termios.B75,
    110:     termios.B110,
    134:     termios.B134,
    150:     termios.B150,
    200:     termios.B200,
    300:     termios.B300,
    600:     termios.B600,
    1200:    termios.B1200,
    1800:    termios.B1800,
    2400:    termios.B2400,
    4800:    termios.B4800,
    9600:    termios.B9600,
    19200:   termios.B19200,
    38400:   termios.B38400,
    57600:   termios.B57600,
    115200:  termios.B115200,
    230400:  termios.B230400,
    460800:  termios.B460800,
    500000:  termios.B500000,
    576000:  termios.B576000,
    921600:  termios.B921600,
    1000000: termios.B1000000,
    1152000: termios.B1152000,
    1500000: termios.B1500000,
    2000000: termios.B2000000,
    2500000: termios.B2500000,
    3000000: termios.B3000000,
    3500000: termios.B3500000,
    4000000: termios.B4000000,
}


def _set_baud_termios2(fd: int, baud: int) -> bool:
    """
    使用 TCGETS2/TCSETS2 + BOTHER 设置任意波特率。
    这种方式绕过标准 termios 波特率常量，让驱动直接使用整数波特率值，
    对 cp210x 等驱动能触发 vendor-specific USB 控制请求，与 Windows 驱动行为一致。
    成功返回 True，不支持时返回 False。
    """
    # struct termios2 在 ARM Linux 上：
    #   c_iflag:  u32
    #   c_oflag:  u32
    #   c_cflag:  u32
    #   c_lflag:  u32
    #   c_line:   u8
    #   c_cc:     u8[19]
    #   c_ispeed: u32
    #   c_ospeed: u32
    # 总大小: 4*4 + 1 + 19 + 4 + 4 = 44 字节
    TERMIOS2_FMT = "IIIIB19sII"  # 44 bytes

    try:
        buf = array.array('b', b'\x00' * struct.calcsize(TERMIOS2_FMT))
        fcntl.ioctl(fd, TCGETS2, buf)
        data = struct.unpack(TERMIOS2_FMT, buf.tobytes())

        c_iflag, c_oflag, c_cflag, c_lflag, c_line, c_cc, c_ispeed, c_ospeed = data

        # 清除旧的波特率位，设置 BOTHER
        c_cflag = (c_cflag & ~CBAUD) | BOTHER
        c_ispeed = baud
        c_ospeed = baud

        packed = struct.pack(TERMIOS2_FMT, c_iflag, c_oflag, c_cflag, c_lflag, c_line, c_cc, c_ispeed, c_ospeed)
        buf = array.array('b', packed)
        fcntl.ioctl(fd, TCSETS2, buf)

        # 回读验证
        buf2 = array.array('b', b'\x00' * struct.calcsize(TERMIOS2_FMT))
        fcntl.ioctl(fd, TCGETS2, buf2)
        data2 = struct.unpack(TERMIOS2_FMT, buf2.tobytes())
        actual_ospeed = data2[7]
        actual_ispeed = data2[6]

        # 允许 2% 误差（USB 转串口芯片的时钟分频不一定精确）
        if actual_ospeed > 0:
            error_ratio = abs(actual_ospeed - baud) / baud
            if error_ratio > 0.02:
                _logger.warning(
                    "Baud rate mismatch via TCSETS2: requested=%d actual=%d (%.1f%% error)",
                    baud, actual_ospeed, error_ratio * 100,
                )
                return False
        _logger.info("Set baud rate %d via TCSETS2/BOTHER (actual: ispeed=%d ospeed=%d)", baud, actual_ispeed, actual_ospeed)
        return True
    except (OSError, struct.error) as e:
        _logger.debug("TCSETS2/BOTHER not available: %s", e)
        return False


def _configure_serial(fd: int, baud: int, parity: str, flow: str, databits: int, stopbits: int) -> None:
    """使用 termios 配置串口参数。波特率优先使用 TCSETS2+BOTHER，fallback 到标准 termios。"""

    # ── 先用标准 termios 配置帧格式（数据位、停止位、校验、流控等）──
    # 读取当前属性
    attrs = termios.tcgetattr(fd)
    # attrs: [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]

    # ── cflag: 数据位 ──
    attrs[2] &= ~termios.CSIZE
    databits_map = {5: termios.CS5, 6: termios.CS6, 7: termios.CS7, 8: termios.CS8}
    if databits not in databits_map:
        raise ValueError(f"Invalid databits: {databits}")
    attrs[2] |= databits_map[databits]

    # ── cflag: 停止位 ──
    if stopbits == 2:
        attrs[2] |= termios.CSTOPB
    else:
        attrs[2] &= ~termios.CSTOPB

    # ── cflag: 奇偶校验 ──
    if parity == "none":
        attrs[2] &= ~termios.PARENB
        attrs[2] &= ~termios.PARODD
    elif parity == "even":
        attrs[2] |= termios.PARENB
        attrs[2] &= ~termios.PARODD
    elif parity == "odd":
        attrs[2] |= termios.PARENB
        attrs[2] |= termios.PARODD
    else:
        raise ValueError(f"Invalid parity: {parity}")

    # ── cflag: 本地连接 + 启用接收 ──
    attrs[2] |= termios.CLOCAL | termios.CREAD

    # ── cflag: 硬件流控 ──
    try:
        crtscts = termios.CRTSCTS
    except AttributeError:
        crtscts = 0o20000000000  # Linux ARM 上的值

    if flow == "rtscts":
        attrs[2] |= crtscts
    else:
        attrs[2] &= ~crtscts

    # ── iflag: 软件流控 & 输入处理 ──
    attrs[0] &= ~(termios.IXON | termios.IXOFF | termios.IXANY)
    if flow == "xonxoff":
        attrs[0] |= termios.IXON | termios.IXOFF

    # 关闭输入特殊字符处理、奇偶校验检查
    attrs[0] &= ~(termios.INPCK | termios.ISTRIP | termios.INLCR |
                  termios.IGNCR | termios.ICRNL | termios.IGNBRK)
    attrs[0] |= termios.IGNPAR

    # ── oflag: 关闭输出处理 ──
    attrs[1] = 0

    # ── lflag: raw 模式 ──
    attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ECHOE |
                  termios.ECHOK | termios.ECHONL | termios.ISIG | termios.IEXTEN)

    # ── cc: 非阻塞读取配置 ──
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0

    # ── 设置波特率（标准 termios 方式，先设一个临时值）──
    # 对于标准波特率，直接 termios 设置；后面再尝试 TCSETS2 覆盖
    baud_const = _BAUD_MAP.get(baud)
    if baud_const is not None:
        attrs[4] = baud_const  # ispeed
        attrs[5] = baud_const  # ospeed
    else:
        # 非标准波特率，先用 B38400 占位，后面用 TCSETS2 设置真实值
        attrs[4] = termios.B38400
        attrs[5] = termios.B38400

    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIOFLUSH)

    # ── 尝试用 TCSETS2 + BOTHER 设置精确波特率 ──
    # 这种方式对 cp210x 等驱动更可靠，能触发 vendor-specific USB 控制请求
    if _set_baud_termios2(fd, baud):
        _logger.info("Baud rate %d set via TCSETS2/BOTHER", baud)
        return

    # ── Fallback: 标准 termios 方式 ──
    if baud_const is None:
        raise ValueError(
            f"Baud rate {baud} is not a standard rate and TCSETS2/BOTHER is not available. "
            f"Supported standard rates: {sorted(_BAUD_MAP.keys())}"
        )

    # 回读验证标准 termios 设置
    verify = termios.tcgetattr(fd)
    actual_ispeed = verify[4]
    actual_ospeed = verify[5]
    if actual_ispeed != baud_const or actual_ospeed != baud_const:
        reverse_map = {v: k for k, v in _BAUD_MAP.items()}
        actual_baud = reverse_map.get(actual_ospeed, f"unknown(0x{actual_ospeed:x})")
        raise ValueError(
            f"Baud rate {baud} not supported by this USB-serial adapter. "
            f"Actual baud rate set: {actual_baud}. "
            f"Try a lower baud rate or use an adapter that supports {baud} (e.g. FT232, CP2104)."
        )
    _logger.info("Baud rate %d set via standard termios", baud)


def _read_sysfs(path: str) -> str:
    """安全读取 sysfs 文件，返回 strip 后的内容，失败返回空字符串"""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, OSError, PermissionError):
        return ""


def _get_usb_device_info(tty_name: str) -> Optional[dict]:
    """
    通过 sysfs 获取 ttyUSB 设备的 USB 详细信息。

    返回 dict:
      {
        "path":         "/dev/ttyUSB4",
        "name":         "CP2102 USB to UART Bridge Controller",
        "manufacturer": "Silicon Labs",
        "vid":          "10c4",
        "pid":          "ea60",
        "driver":       "cp210x",
        "serial":       "0001",
      }
    如果无法读取信息返回 None。
    """
    tty_sysfs = f"/sys/class/tty/{tty_name}"
    device_link = os.path.join(tty_sysfs, "device")
    if not os.path.islink(device_link):
        return None

    try:
        # device symlink resolves to: .../2-1.4:1.0/ttyUSB4  (tty port dir)
        tty_port_path = os.path.realpath(device_link)
        # 上一级 = USB interface: .../2-1.4:1.0
        usb_iface_path = os.path.dirname(tty_port_path)
        # 再上一级 = USB device: .../2-1.4  (这里才有 idVendor, idProduct, product 等)
        usb_dev_path = os.path.dirname(usb_iface_path)

        vid = _read_sysfs(os.path.join(usb_dev_path, "idVendor"))
        pid = _read_sysfs(os.path.join(usb_dev_path, "idProduct"))
        product = _read_sysfs(os.path.join(usb_dev_path, "product"))
        manufacturer = _read_sysfs(os.path.join(usb_dev_path, "manufacturer"))
        serial = _read_sysfs(os.path.join(usb_dev_path, "serial"))

        # 获取 USB-serial 驱动名称（在 USB interface 层级）
        driver_link = os.path.join(usb_iface_path, "driver")
        driver = ""
        if os.path.islink(driver_link):
            driver = os.path.basename(os.path.realpath(driver_link))

        return {
            "path": f"/dev/{tty_name}",
            "name": product or tty_name,
            "manufacturer": manufacturer,
            "vid": vid,
            "pid": pid,
            "driver": driver,
            "serial": serial,
        }
    except OSError as e:
        _logger.debug("Failed to read sysfs info for %s: %s", tty_name, e)
        return None


# 内部设备使用的 USB-serial 驱动（4G Modem 的 option 驱动等）
_INTERNAL_DRIVERS = {"option", "qmi_wwan", "cdc_acm"}


def _is_external_serial(info: dict) -> bool:
    """
    判断 USB 串口设备是否为外接设备（非板载 modem 等内部设备）。
    内部设备特征：
      - 驱动为 option（4G modem AT 端口）、cdc_acm 等
    外接设备特征：
      - 驱动为 cp210x、ch341、ftdi_sio、pl2303 等串口转换芯片
    """
    driver = info.get("driver", "")
    if driver in _INTERNAL_DRIVERS:
        return False
    # 如果没有驱动信息，保守地排除
    if not driver:
        return False
    return True


class SerialApi:
    """串口 API：列表查询 + WebSocket 直连桥 + 热插拔检测（仅外接设备）"""

    __need_update = False

    def __init__(self) -> None:
        self._prev_devices: Optional[list] = None  # list of device path strings for change detection

    @staticmethod
    def _scan_external_serial() -> list:
        """
        扫描 /dev/ttyUSB* 中的 **外接** USB 串口设备，
        排除板载 4G modem 等内部设备（通过驱动名过滤）。
        返回设备信息 dict 列表。
        """
        result = []
        for dev_path in sorted(glob.glob("/dev/ttyUSB*")):
            tty_name = os.path.basename(dev_path)
            info = _get_usb_device_info(tty_name)
            if info and _is_external_serial(info):
                result.append(info)
        # 同时扫描 ttyACM* (如 Arduino 等设备)，但排除内部 cdc_acm modem 端口
        for dev_path in sorted(glob.glob("/dev/ttyACM*")):
            tty_name = os.path.basename(dev_path)
            info = _get_usb_device_info(tty_name)
            if info and _is_external_serial(info):
                result.append(info)
        return result

    async def get_state(self) -> dict:
        devices = self._scan_external_serial()
        return {"exist": len(devices) > 0, "devices": devices}

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        """每 3 秒轮询外接 USB 串口设备列表，变化时 yield 事件通知前端"""
        while True:
            devices = self._scan_external_serial()
            device_paths = [d["path"] for d in devices]
            exist = len(devices) > 0
            if self.__need_update or device_paths != self._prev_devices:
                yield {"exist": exist, "devices": devices}
                if self._prev_devices is not None:
                    added = set(device_paths) - set(self._prev_devices)
                    removed = set(self._prev_devices) - set(device_paths)
                    if added:
                        _logger.info("External serial device(s) added: %s", added)
                    if removed:
                        _logger.info("External serial device(s) removed: %s", removed)
                self._prev_devices = device_paths
                self.__need_update = False
            await asyncio.sleep(3)

    async def trigger_state(self) -> None:
        self.__need_update = True

    # ── /serial/list ──────────────────────────────────────────────────────
    @exposed_http("GET", "/serial/list")
    async def __list_handler(self, _: Request) -> Response:
        """列出当前系统中外接的 USB 串口设备（含设备详情）"""
        try:
            devices = self._scan_external_serial()
            return make_json_response({"devices": devices})
        except Exception as ex:
            _logger.error("Failed to list serial devices: %s", ex)
            return make_json_exception(BadRequestError(f"Failed to list serial devices: {ex}"), 500)

    # ── /serial/check ─────────────────────────────────────────────────────
    @exposed_http("GET", "/serial/check")
    async def __check_handler(self, req: Request) -> Response:
        """
        预检串口参数：打开设备、配置参数、验证波特率，然后关闭。
        成功返回 {"ok": true}，失败返回错误信息。
        """
        dev      = req.query.get("dev", "/dev/ttyS2")
        baud_str = req.query.get("baud", "115200")
        parity   = req.query.get("parity", "none")
        flow     = req.query.get("flow", "none")
        dbs_str  = req.query.get("databits", "8")
        sbs_str  = req.query.get("stopbits", "1")

        try:
            baud     = int(baud_str)
            databits = int(dbs_str)
            stopbits = int(sbs_str)
        except ValueError as ex:
            return make_json_exception(BadRequestError(f"Invalid parameter: {ex}"), 400)

        if not dev.startswith("/dev/"):
            return make_json_exception(BadRequestError(f"Invalid device path: {dev}"), 400)

        fd = None
        try:
            fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            _configure_serial(fd, baud, parity, flow, databits, stopbits)
            return make_json_response({"ok": True})
        except OSError as ex:
            return make_json_exception(BadRequestError(f"Cannot open {dev}: {ex}"), 400)
        except (ValueError, Exception) as ex:
            return make_json_exception(BadRequestError(str(ex)), 400)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass

    # ── /serial/ws ────────────────────────────────────────────────────────
    @exposed_http("GET", "/serial/ws")
    async def __ws_handler(self, req: Request) -> WebSocketResponse:
        """
        WebSocket → 串口直连桥。

        Query 参数:
          dev       串口设备路径，默认 /dev/ttyS2
          baud      波特率，默认 115200
          parity    none | odd | even，默认 none
          flow      none | xonxoff | rtscts，默认 none
          databits  5 | 6 | 7 | 8，默认 8
          stopbits  1 | 2，默认 1
        """
        dev      = req.query.get("dev", "/dev/ttyS2")
        baud_str = req.query.get("baud", "115200")
        parity   = req.query.get("parity", "none")
        flow     = req.query.get("flow", "none")
        dbs_str  = req.query.get("databits", "8")
        sbs_str  = req.query.get("stopbits", "1")

        # 参数校验
        try:
            baud     = int(baud_str)
            databits = int(dbs_str)
            stopbits = int(sbs_str)
        except ValueError as ex:
            raise BadRequestError(f"Invalid serial parameter: {ex}") from ex

        if not dev.startswith("/dev/"):
            raise BadRequestError(f"Invalid device path: {dev}")
        if parity not in ("none", "odd", "even"):
            raise BadRequestError(f"Invalid parity: {parity}")
        if flow not in ("none", "xonxoff", "rtscts"):
            raise BadRequestError(f"Invalid flow: {flow}")
        if databits not in (5, 6, 7, 8):
            raise BadRequestError(f"Invalid databits: {databits}")
        if stopbits not in (1, 2):
            raise BadRequestError(f"Invalid stopbits: {stopbits}")

        # 打开串口
        try:
            fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as ex:
            raise BadRequestError(f"Cannot open {dev}: {ex}") from ex

        try:
            _configure_serial(fd, baud, parity, flow, databits, stopbits)
        except Exception as ex:
            os.close(fd)
            raise BadRequestError(f"Failed to configure {dev}: {ex}") from ex

        _logger.info(
            "Serial WS connected: dev=%s baud=%d parity=%s flow=%s databits=%d stopbits=%d",
            dev, baud, parity, flow, databits, stopbits,
        )

        # 升级为 WebSocket
        ws = WebSocketResponse(heartbeat=30.0)
        await ws.prepare(req)

        loop = asyncio.get_event_loop()
        read_queue: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()

        def _on_serial_readable() -> None:
            """串口可读回调：将数据放入队列供协程发送"""
            try:
                data = os.read(fd, 4096)
                if data:
                    read_queue.put_nowait(data)
            except OSError as e:
                _logger.debug("Serial read error: %s", e)
                read_queue.put_nowait(None)  # None 表示串口错误/关闭

        loop.add_reader(fd, _on_serial_readable)

        async def _serial_to_ws() -> None:
            """串口 → WebSocket 转发协程"""
            while not ws.closed:
                try:
                    chunk = await asyncio.wait_for(read_queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    continue
                if chunk is None:
                    # 串口读取出错，通知前端
                    try:
                        await ws.close()
                    except Exception:
                        pass
                    return
                try:
                    await ws.send_bytes(chunk)
                except Exception as ex:
                    _logger.debug("WS send error: %s", ex)
                    return

        reader_task = asyncio.ensure_future(_serial_to_ws())

        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    try:
                        os.write(fd, msg.data)
                    except OSError as ex:
                        _logger.error("Serial write error: %s", ex)
                        break
                elif msg.type == WSMsgType.TEXT:
                    try:
                        os.write(fd, msg.data.encode("utf-8", errors="replace"))
                    except OSError as ex:
                        _logger.error("Serial write error: %s", ex)
                        break
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        finally:
            reader_task.cancel()
            try:
                loop.remove_reader(fd)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass
            _logger.info("Serial WS disconnected: dev=%s", dev)

        return ws
