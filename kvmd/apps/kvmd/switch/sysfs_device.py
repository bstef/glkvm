# ==========================================================================
#
#   Sysfs-based Device implementation for KVMD
#   Replace serial-based Device with Linux sysfs control
#
# ==========================================================================

from pathlib import Path
from typing import Dict, List
from .lib import get_logger
import asyncio
import subprocess
import time
# =====
class DeviceError(Exception):
    pass


class Device:
    """
    Sysfs-backed replacement for kvmd.device.Device

    This class exposes a Device-like interface but operates purely
    via Linux sysfs files instead of serial protocol.
    """
    __channel_count = 4
    __restore_scheduled = False

    # ===== 固定 sysfs 路径 =====
    HDMIPATH = "3-0058"
    CHANNEL_FILE = Path(f"/sys/bus/i2c/devices/{HDMIPATH}/channel")
    USB_HOST_POWER_FILE = Path(f"/sys/bus/i2c/devices/{HDMIPATH}/usb_host_power")
    USB_HOST_CHANNEL_FILE = Path(f"/sys/bus/i2c/devices/{HDMIPATH}/usb_host_channel")
    HDMI_STATUS_FILE = Path(f"/sys/bus/i2c/devices/{HDMIPATH}/hdmi_status")
    USB_STATUS_FILE = Path(f"/sys/bus/i2c/devices/{HDMIPATH}/usb_otg_status")

    DWC3_DEVICE_ID = "21500000.usb"
    DWC3_DRIVER_DIR = Path("/sys/bus/platform/drivers/dwc3")
    DWC3_BIND_FILE = DWC3_DRIVER_DIR / "bind"
    DWC3_UNBIND_FILE = DWC3_DRIVER_DIR / "unbind"
    GADGET_DIR = Path("/sys/kernel/config/usb_gadget/rockchip")
    GADGET_PROFILE_DIR = GADGET_DIR / "configs/b.1"
    GADGET_UDC_FILE = GADGET_DIR / "UDC"
    CAMERA_FUNCTION_LINK = GADGET_PROFILE_DIR / "uvc.gs6"
    UVC_COOLDOWN_FILE = Path("/var/run/reset_uvc_udc.cooldown")
    HID_SUSPEND_FILE = Path("/var/run/kvmd-hid-otg.suspend")
    HID_DEVICE_NAMES = ("hidg0", "hidg1", "hidg2", "hidg3")

    USB_DRIVER_DIR = Path("/sys/bus/usb/drivers/usb")
    USB_BIND_FILE = USB_DRIVER_DIR / "bind"
    USB_UNBIND_FILE = USB_DRIVER_DIR / "unbind"
    USB_DEVICES_DIR = Path("/sys/bus/usb/devices")

    UDC_CLASS_DIR = Path("/sys/class/udc")
    # FIRST_SWITCH = True

    # ===== 配置持久化 =====
    CONF_DIR = Path("/etc/kvmd")
    CONF_FILE = CONF_DIR / "channel.conf"

    def __init__(self, device: str | None = None) -> None:
        self.__active_port = -1
        self.__switch_lock = asyncio.Lock()
        self._device = device
        # init 阶段：只读配置，不动硬件
        self.__saved_channel: int | None = self.__load_channel()

        # 像 upgrade.py 一样：丢给 event loop 一个延后任务
        if self.__saved_channel is not None and not Device.__restore_scheduled:
            try:
                Device.__restore_scheduled = True
                asyncio.get_event_loop().create_task(
                    self.__delayed_restore_channel()
                )
            except RuntimeError:
                Device.__restore_scheduled = False

    async def _async_sleep(self, seconds: float) -> None:
        """ 异步睡眠：供协程调用链使用，不阻塞事件循环 """
        await asyncio.sleep(seconds)

    # ========== UDC 检测：同步+异步双版本 ==========
    def _udc_has_device(self, device_id: str) -> bool:
        if not self.UDC_CLASS_DIR.exists():
            return False
        return (self.UDC_CLASS_DIR / device_id).exists()
    def _get_current_udc(self) -> str | None:
        """读取gadget绑定UDC"""
        try:
            val = self.GADGET_UDC_FILE.read_text().strip()
            return val if val else None
        except OSError:
            return None

    def _is_camera_enabled(self) -> bool:
        """检查当前OTG profile是否启用了UVC camera"""
        return self.CAMERA_FUNCTION_LINK.is_symlink()

    def _touch_uvc_cooldown(self) -> None:
        try:
            self.UVC_COOLDOWN_FILE.touch()
        except Exception as e:
            get_logger().warning("set_channel: touch UVC cooldown failed (ignored): %s", e)

    def _set_hid_suspended(self, suspended: bool) -> None:
        try:
            if suspended:
                self.HID_SUSPEND_FILE.touch()
            else:
                self.HID_SUSPEND_FILE.unlink(missing_ok=True)
        except Exception as e:
            get_logger().warning("set_channel: set HID suspend=%s failed (ignored): %s", suspended, e)

    def _get_hid_fd_holders(self) -> list[str]:
        holders: list[str] = []
        hid_names = set(self.HID_DEVICE_NAMES)
        try:
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                fd_dir = proc / "fd"
                try:
                    comm = (proc / "comm").read_text().strip()
                except Exception:
                    comm = "?"
                try:
                    for fd in fd_dir.iterdir():
                        try:
                            target = fd.resolve(strict=True)
                        except Exception:
                            continue
                        if target.parent == Path("/dev") and target.name in hid_names:
                            holders.append(f"{proc.name}/{comm}:{fd.name}->{target}")
                except Exception:
                    continue
        except Exception as e:
            get_logger().warning("set_channel: scan HID fd holders failed (ignored): %s", e)
        return holders

    async def _async_wait_hid_fds_released(self, timeout: float = 3.0) -> bool:
        logger = get_logger()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            holders = self._get_hid_fd_holders()
            if not holders:
                logger.info("set_channel: HID fds released")
                return True
            logger.info("set_channel: waiting HID fds released: %s", holders)
            await self._async_sleep(0.1)
        holders = self._get_hid_fd_holders()
        if holders:
            logger.warning("set_channel: timeout waiting HID fds released: %s", holders)
            return False
        return True

    def _is_rkipc_running(self) -> bool:
        try:
            for name in Path("/proc").iterdir():
                if not name.name.isdigit():
                    continue
                try:
                    if (name / "comm").read_text().strip() == "rkipc":
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    async def _async_wait_rkipc_stopped(self, timeout: float = 5.0) -> bool:
        logger = get_logger()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if not self._is_rkipc_running():
                return True
            await self._async_sleep(0.1)
        logger.warning("set_channel: timeout waiting rkipc stopped")
        return False

    def _get_udc_state(self) -> str:
        udc = self._get_current_udc()
        if not udc:
            return ""
        try:
            return (self.UDC_CLASS_DIR / udc / "state").read_text().strip()
        except OSError:
            return ""

    async def _async_wait_camera_ready(self, timeout: float = 10.0, stable_time: float = 2.0) -> bool:
        logger = get_logger()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        stable_since: float | None = None
        while loop.time() < deadline:
            rkipc_running = self._is_rkipc_running()
            udc_state = self._get_udc_state()
            if rkipc_running and udc_state == "configured":
                if stable_since is None:
                    stable_since = loop.time()
                stable_for = loop.time() - stable_since
                if stable_for >= stable_time:
                    logger.info("set_channel: camera ready, stable_for=%.1f", stable_for)
                    return True
                logger.info(
                    "set_channel: camera settling, stable_for=%.1f/%.1f, rkipc_running=%s, udc_state=%s",
                    stable_for,
                    stable_time,
                    rkipc_running,
                    udc_state or "unknown",
                )
            else:
                stable_since = None
                logger.info(
                    "set_channel: camera not ready, rkipc_running=%s, udc_state=%s",
                    rkipc_running,
                    udc_state or "unknown",
                )
            await self._async_sleep(0.2)
        return False

    async def _async_run_shell(self, cmd: str, timeout: float) -> None:
        logger = get_logger()
        logger.info("set_channel: run shell cmd=%s", cmd)
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise DeviceError(f"Command timeout: {cmd}")

        if stdout:
            logger.info("set_channel: command stdout: %s", stdout.decode(errors="ignore").strip())
        if proc.returncode != 0:
            err = stderr.decode(errors="ignore").strip()
            raise DeviceError(f"Command failed rc={proc.returncode}: {cmd}: {err}")
        if stderr:
            logger.warning("set_channel: command stderr: %s", stderr.decode(errors="ignore").strip())

    async def _async_wait_udc_device(self, device_id: str, timeout: float = 2.0, interval: float = 0.1) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._udc_has_device(device_id):
                return True
            await self._async_sleep(interval)
        return False

    # ========== USB 端口查找 ==========
    def _find_usb_port(self) -> str | None:
        for port in ("1-1", "2-1"):
            if (self.USB_DEVICES_DIR / port).exists():
                return port
        return None

    # ========== USB_HOST 通道切换 ==========
    async def _async_simple_switch_channel(self, ch: int) -> None:
        logger = get_logger()
        logger.info("set_channel: async_simple_switch_channel path=%s value=0", self.USB_HOST_POWER_FILE)
        self._write_file(self.USB_HOST_POWER_FILE, "0")
        await self._async_sleep(1.0)
        self._write_file(self.USB_HOST_CHANNEL_FILE, str(ch))

    async def _async_switch_channel_mux_only(self, ch: int) -> None:
        self._write_file(self.CHANNEL_FILE, str(ch))
        await self._async_simple_switch_channel(ch)

    async def _async_reset_otg_for_camera(self) -> None:
        await self._async_run_shell("kvmd-otgconf --reset-gadget", timeout=30.0)

    # ------------------------------------------------------------------
    # 生命周期（保持与 Device 兼容）
    # ------------------------------------------------------------------
    def __enter__(self) -> "SysfsDevice":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    # ------------------------------------------------------------------
    # 基础能力
    # ------------------------------------------------------------------
    def has_device(self) -> bool:
        """
        Check whether sysfs device exists.
        """
        return self.CHANNEL_FILE.exists()

    def get_fd(self) -> int:
        """
        Serial Device exposes fd; sysfs does not.
        Keep for interface compatibility.
        """
        raise DeviceError("SysfsDevice has no file descriptor")

    # ------------------------------------------------------------------
    # sysfs helpers
    # ------------------------------------------------------------------
    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text().strip()
        except Exception as ex:
            raise DeviceError(ex)

    def _write_file(self, path: Path, value: str) -> None:
        logger = get_logger()
        logger.info("set_channel: write_file path=%s value=%s", path, value)
        try:
            path.write_text(value)
        except Exception as ex:
            raise DeviceError(ex)
    
    # ------------------------------------------------------------------
    # ===== Channel persistence helpers =====
    # ------------------------------------------------------------------
    async def __delayed_restore_channel(self) -> None:
        ch = self.__saved_channel
        self.__saved_channel = None

        if ch is None:
            return

        try:
            logger = get_logger()
            if self._is_camera_enabled():
                logger.info("set_channel: delayed restore wait camera ready before channel=%s", ch)
                if not await self._async_wait_camera_ready(timeout=15.0, stable_time=2.0):
                    logger.warning("set_channel: delayed restore camera ready timeout, continue channel=%s", ch)

                current = self.get_current_channel()
                logger.info("set_channel: delayed restore target=%s current=%s", ch, current)
                if current != ch:
                    await self._async_set_channel(ch)
                print(f"[sysfs-device] restored channel {ch}")
                return

            await asyncio.sleep(0)
            self._write_file(self.CHANNEL_FILE, str(ch))
            # 协程内使用异步版本，不阻塞事件循环
            await self._async_simple_switch_channel(ch)
            udc_ready = await self._async_wait_udc_device(self.DWC3_DEVICE_ID, timeout=2.0)
            if not udc_ready:
                self._write_file(self.DWC3_BIND_FILE, self.DWC3_DEVICE_ID)
            print(f"[sysfs-device] restored channel {ch}")
        except Exception as e:
            print(f"[sysfs-device] restore channel failed: {e}")

    def __load_channel(self) -> int | None:
        try:
            if self.CONF_FILE.exists():
                return int(self.CONF_FILE.read_text().strip())
        except Exception as e:
            print(f"[sysfs-device] load channel failed: {e}")
        return None

    def __save_channel(self, ch: int) -> None:
        try:
            self.CONF_DIR.mkdir(parents=True, exist_ok=True)
            self.CONF_FILE.write_text(str(ch))
        except Exception as e:
            print(f"[sysfs-device] save channel failed: {e}")

    # ------------------------------------------------------------------
    # Channel
    # ------------------------------------------------------------------
    def get_current_channel(self) -> int:
        """
        Parse:
            'Current Channel : 0'
        """
        text = self._read_file(self.CHANNEL_FILE)
        try:
            return int(text.split(":")[-1].strip())
        except Exception:
            raise DeviceError(f"Invalid channel format: {text}")

    async def _async_set_channel(self, ch: int) -> None:
        """ 异步版本：供KVMD异步接口/协程使用，不阻塞事件循环 """
        ch = int(ch)
        logger = get_logger()
        if not 0 <= ch <= 3:
            raise ValueError(f"invalid channel: {ch}")

        camera_enabled = self._is_camera_enabled()
        logger.info("set_channel: ch=%s camera_enabled=%s", ch, camera_enabled)
        if camera_enabled:
            await self._async_set_channel_with_camera(ch)
            return

        logger.info("set_channel: ch=%s wait_udc_device", ch)
        self.CHANNEL_FILE.write_text(str(ch))
        udc_ready = await self._async_wait_udc_device(self.DWC3_DEVICE_ID, timeout=2.0)

        logger.info("set_channel: ch=%s udc_ready=%s", ch, udc_ready)

        channel_switched = False
        try:
            usb_port = self._find_usb_port()
            logger.info("set_channel: usb_port before switch=%s", usb_port or "none")

            if usb_port is not None:
                try:
                    self._write_file(self.USB_UNBIND_FILE, usb_port)
                except Exception as e:
                    logger.warning("set_channel: USB unbind failed (ignored): %s", e)

            # 👇 即使上面失败，这里依然会执行！
            try:
                self._write_file(self.DWC3_UNBIND_FILE, self.DWC3_DEVICE_ID)
            except Exception as e:
                logger.warning("set_channel: DWC3 unbind failed (ignored): %s", e)
            await self._async_sleep(0.5)

            # 协程内调用异步切换，不阻塞
            await self._async_simple_switch_channel(ch)
            channel_switched = True

            await self._async_sleep(0.8)
            try:
                self._write_file(self.DWC3_BIND_FILE, self.DWC3_DEVICE_ID)
            except Exception as e:
                logger.error("set_channel: DWC3 bind failed: %s", e)

            usb_port = self._find_usb_port()
            if usb_port is not None:
                try:
                    self._write_file(self.USB_BIND_FILE, usb_port)
                except Exception as e:
                    logger.warning("set_channel: USB bind failed (ignored): %s", e)

            logger.info("set_channel: full dwc3 switch finished, ch=%s", ch)
            # 异步切换会导致 /sys/kernel/config/usb_gadget/rockchip/UDC 被清除
            cur_udc = self._get_current_udc()
            target = self.DWC3_DEVICE_ID
            if cur_udc != target:
                try:
                    self._write_file(self.GADGET_UDC_FILE, target)
                    logger.info(f"bind gadget UDC: {target}")
                except Exception as e:
                    logger.warning("set_channel: write GADGET_UDC failed (ignored): %s", e)
                    
        finally:
            udc_ready = await self._async_wait_udc_device(self.DWC3_DEVICE_ID, timeout=2.0)
            if not udc_ready:
                self._write_file(self.DWC3_BIND_FILE, self.DWC3_DEVICE_ID)
            if channel_switched:
                self.__save_channel(ch)
                channel_switched = False

    async def _async_set_channel_with_camera(self, ch: int) -> None:
        logger = get_logger()
        logger.info("set_channel: camera enabled, using full OTG rebuild path, ch=%s", ch)
        rkipc_stopped = False
        hid_suspended = False
        channel_switched = False
        try:
            self._set_hid_suspended(True)
            hid_suspended = True
            await self._async_wait_hid_fds_released(timeout=3.0)

            # 与/system/otg_functions保持一致：UDC rebind后extcon可能延迟触发reset_uvc_udc，
            # 先touch cooldown避免二次rebind打断rkipc/UVC初始化。
            self._touch_uvc_cooldown()
            await self._async_run_shell("/etc/init.d/S99rkipc full_stop", timeout=10.0)
            rkipc_stopped = True
            await self._async_wait_rkipc_stopped(timeout=5.0)

            # Camera/UVC启用时先停rkipc，再切硬件mux，随后reset当前gadget。
            # 切通道不改变function组合，因此不需要kvmd-otg stop/start完整重建gadget。
            await self._async_switch_channel_mux_only(ch)
            channel_switched = True
            await self._async_reset_otg_for_camera()
            logger.info("set_channel: camera OTG reset finished, ch=%s", ch)
        finally:
            if rkipc_stopped:
                try:
                    await self._async_run_shell(
                        "/etc/init.d/S99rkipc full_start >/dev/null 2>&1",
                        timeout=10.0,
                    )
                    if not await self._async_wait_camera_ready(timeout=10.0, stable_time=2.0):
                        logger.warning("set_channel: timeout waiting camera ready after switch")
                except Exception as e:
                    logger.warning("set_channel: failed to start rkipc after camera switch: %s", e)
            if hid_suspended:
                self._set_hid_suspended(False)
            if channel_switched:
                self.__save_channel(ch)
                channel_switched = False

    # ------------------------------------------------------------------
    # HDMI status
    # ------------------------------------------------------------------
    def get_hdmi_status(self) -> Dict[int, bool]:
        """
        Return example:
        {
            0: True,
            1: False,
            2: False,
            3: True,
        }
        """
        raw = self._read_file(self.HDMI_STATUS_FILE).splitlines()
        status: Dict[int, bool] = {}

        for idx, line in enumerate(raw):
            status[idx] = "Connected" in line

        return status

    # ------------------------------------------------------------------
    # USB OTG status
    # ------------------------------------------------------------------
    def get_usb_otg_status(self) -> Dict[int, bool]:
        """
        Return example:
        {
            0: True,
            1: False,
            2: False,
            3: True,
        }
        """
        raw = self._read_file(self.USB_STATUS_FILE).splitlines()
        status: Dict[int, bool] = {}

        for idx, line in enumerate(raw):
            status[idx] = "Connected" in line
        return status

    def get_usb_host_connected(self) -> bool:
        """
        Detect external USB-A device by:
            lsusb | wc -l

        Baseline:
            3 -> no device
            4+ -> device connected
        """
        try:
            result = subprocess.run(
                ["lsusb"],
                capture_output=True,
                text=True,
                timeout=1,
            )

            if result.returncode != 0:
                return False

            line_count = len(result.stdout.strip().splitlines())

            return line_count > 3

        except Exception:
            return False


    def request_state(self) -> dict:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
        state: dict = {}
        
        # if x_summary:
        self.__active_port = self.get_current_channel()
        state["summary"] = {
            "active_port": self.__active_port,
            "active_id": f"1.{self.__active_port + 1}",
            "synced": True,
        }
        
        # if x_usb:
        usb_status = self.get_usb_otg_status()
        state["usb"] = {"links": [usb_status.get(ch, False) for ch in range(self.__channel_count)]}
        # if x_video:
        hdmi_status = self.get_hdmi_status()
        state["video"] = {"links": [hdmi_status.get(ch, False) for ch in range(self.__channel_count)]}
        print(f"{state}")
        return state


    # ------------------------------------------------------------------
    # ===== Device-like request APIs（异步版，适配KVMD aiohttp） =====
    # ------------------------------------------------------------------
    async def async_request_switch(self, unit: int, ch: int) -> int:
        """
        Async switch request for aiohttp/KVMD call chains.
        """
        async with self.__switch_lock:
            await self._async_set_channel(ch)
        return 0  # rid placeholder

    # ------------------------------------------------------------------
    # ===== Unsupported / Stub APIs (for compatibility) =====
    # ------------------------------------------------------------------
    def request_reboot(self, unit: int, bootloader: bool) -> int:
        raise DeviceError("Reboot not supported via sysfs")

    def request_beacon(self, unit: int, ch: int, on: bool) -> int:
        return 0

    def request_atx_leds(self) -> int:
        return 0

    def request_atx_cp(self, unit: int, ch: int, delay_ms: int) -> int:
        return 0

    def request_atx_cr(self, unit: int, ch: int, delay_ms: int) -> int:
        return 0

    def request_set_edid(self, unit: int, ch: int, edid) -> int:
        return 0

    def request_set_dummy(self, unit: int, ch: int, on: bool) -> int:
        return 0

    def request_set_colors(self, unit: int, ch: int, colors) -> int:
        return 0

    def request_set_quirks(self, unit: int, ignore_hpd: bool) -> int:
        return 0

    def read_all(self):
        return []