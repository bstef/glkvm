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


import copy
import os
import asyncio

from typing import AsyncGenerator
from typing import Any

from evdev import ecodes

from ....logging import get_logger

from .... import aiomulti
from .... import usb

from ....yamlconf import Option

from ....validators.basic import valid_bool
from ....validators.basic import valid_int_f1
from ....validators.basic import valid_float_f01
from ....validators.os import valid_abs_path

from .. import BaseHid

from .keyboard import KeyboardProcess
from .mouse import MouseProcess
from .touch import TouchProcess

from ....utils import get_model_name

model_name = get_model_name()

# =====
class Plugin(BaseHid):  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        ignore_keys: list[str],
        mouse_x_range: dict[str, Any],
        mouse_y_range: dict[str, Any],
        jiggler: dict[str, Any],

        keyboard: dict[str, Any],
        mouse: dict[str, Any],
        mouse_alt: dict[str, Any],
        touch: dict[str, Any],
        noop: bool,

        udc: str,  # XXX: Not from options, see /kvmd/apps/kvmd/__init__.py for details
    ) -> None:

        super().__init__(ignore_keys=ignore_keys, **mouse_x_range, **mouse_y_range, **jiggler)

        self.__udc = udc

        self.__notifier = aiomulti.AioProcessNotifier()

        win98_fix = mouse.pop("absolute_win98_fix")
        common = {"notifier": self.__notifier, "noop": noop}

        self.__keyboard_proc = KeyboardProcess(**common, **keyboard)
        self.__mouse_current = self.__mouse_proc = MouseProcess(**common, **mouse)

        self.__mouse_alt_proc: (MouseProcess | None) = None
        self.__mouses: dict[str, MouseProcess] = {}
        if mouse_alt["device_path"]:
            self.__mouse_alt_proc = MouseProcess(
                absolute=(not mouse["absolute"]),
                **common,
                **mouse_alt,
            )
            self.__mouses = {
                "usb": (self.__mouse_proc if mouse["absolute"] else self.__mouse_alt_proc),
                "usb_rel": (self.__mouse_alt_proc if mouse["absolute"] else self.__mouse_proc),
            }
            if win98_fix:
                # На самом деле мультимышка и win95 не зависят друг от друга,
                # но так было проще реализовать переключение режимов
                self.__mouses["usb_win98"] = self.__mouses["usb"]

        self.__touch_proc: (TouchProcess | None) = None
        self.__touch_device_path = ""
        if touch.get("device_path"):
            self.__touch_proc = TouchProcess(**common, **touch)
            self.__touch_device_path = touch["device_path"]
        self.__touch_mode = False
        # Last known pointer position while in usb_touch mode (mouse-gesture emulation).
        self.__touch_sim_x = 0
        self.__touch_sim_y = 0
        self.__touch_sim_down = False

        self.__hybrid_mode = False
        self.__mouse_abs: (MouseProcess | None) = None
        self.__mouse_rel: (MouseProcess | None) = None
        self.__mouse_device_paths: dict[str, str] = {}
        if self.__mouses:
            self.__mouse_abs = self.__mouses["usb"]
            self.__mouse_rel = self.__mouses["usb_rel"]
            if mouse["absolute"]:
                self.__mouse_device_paths["usb"] = mouse["device_path"]
                self.__mouse_device_paths["usb_rel"] = mouse_alt["device_path"]
            else:
                self.__mouse_device_paths["usb"] = mouse_alt["device_path"]
                self.__mouse_device_paths["usb_rel"] = mouse["device_path"]
        else:
            output = ("usb" if mouse["absolute"] else "usb_rel")
            self.__mouse_device_paths[output] = mouse["device_path"]

        self._set_jiggler_absolute(self.__mouse_current.is_absolute())

        # 添加 link_state 监听相关属性
        if model_name == "rmq1":
            self.__link_state_paths = [
                "/sys/kernel/debug/8000000.dwc3/link_state",
            ]
        else:
            self.__link_state_paths = [
                "/sys/kernel/debug/ffd00000.dwc3/link_state",
                "/sys/kernel/debug/usb/21500000.usb/link_state"
            ]
        self.__link_state_path = None
        self.__connected_state = None

    @classmethod
    def get_plugin_options(cls) -> dict:
        return {
            "keyboard": {
                "device":         Option("/dev/hidg0", type=valid_abs_path, unpack_as="device_path"),
                "select_timeout": Option(0.1, type=valid_float_f01),
                "queue_timeout":  Option(0.1, type=valid_float_f01),
                "write_retries":  Option(150, type=valid_int_f1),
            },
            "mouse": {
                "device":             Option("/dev/hidg1", type=valid_abs_path, unpack_as="device_path"),
                "select_timeout":     Option(0.1,   type=valid_float_f01),
                "queue_timeout":      Option(0.1,   type=valid_float_f01),
                "write_retries":      Option(150,   type=valid_int_f1),
                "absolute":           Option(True,  type=valid_bool),
                "absolute_win98_fix": Option(False, type=valid_bool),
                "horizontal_wheel":   Option(True,  type=valid_bool),
            },
            "mouse_alt": {
                "device":           Option("/dev/kvmd-hid-mouse-alt", type=valid_abs_path, if_empty="", unpack_as="device_path"),
                "select_timeout":   Option(0.1,  type=valid_float_f01),
                "queue_timeout":    Option(0.1,  type=valid_float_f01),
                "write_retries":    Option(150,  type=valid_int_f1),
                # No absolute option here, initialized by (not mouse.absolute)
                # Also no absolute_win98_fix
                "horizontal_wheel": Option(True, type=valid_bool),
            },
            "touch": {
                "device":         Option("/dev/hidg3", type=valid_abs_path, if_empty="", unpack_as="device_path"),
                "select_timeout": Option(0.1, type=valid_float_f01),
                "queue_timeout":  Option(0.1, type=valid_float_f01),
                "write_retries":  Option(150, type=valid_int_f1),
            },
            "noop": Option(False, type=valid_bool),
            **cls._get_base_options(),
        }

    def sysprep(self) -> None:
        udc = usb.find_udc(self.__udc)
        get_logger(0).info("Using UDC %s", udc)
        self.__keyboard_proc.start(udc)
        self.__mouse_proc.start(udc)
        if self.__mouse_alt_proc:
            self.__mouse_alt_proc.start(udc)
        if self.__touch_proc:
            self.__touch_proc.start(udc)

    async def systask(self) -> None:
        """系统任务：启动 link_state 监听和父类的 jiggler 功能"""
        # 查找存在的 link_state 文件
        self.__link_state_path = self.__find_link_state_file()
        
        if self.__link_state_path:
            # 初始化连接状态
            self.__connected_state = self.__read_link_state()
            get_logger(0).debug("Starting link_state monitoring for: %s, initial state: %s", 
                              self.__link_state_path, self.__connected_state)
        
        # 创建两个任务：父类的 jiggler 功能和 link_state 监听
        tasks = []
        
        # 添加父类的 jiggler 任务
        tasks.append(asyncio.create_task(super().systask()))
        
        # 添加 link_state 监听任务（如果找到文件）
        if self.__link_state_path:
            tasks.append(asyncio.create_task(self.__monitor_link_state()))
        
        # 等待所有任务完成
        try:
            await asyncio.gather(*tasks)
        except Exception:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    def __find_link_state_file(self) -> (str | None):
        """查找存在的 link_state 文件"""
        for path in self.__link_state_paths:
            if os.path.exists(path):
                get_logger(0).info("Found link_state file: %s", path)
                return path
        get_logger(0).debug("No link_state file found in any of the expected paths: %s", self.__link_state_paths)
        return None

    def __read_link_state(self) -> (bool | None):
        """读取 link_state 文件内容并解析连接状态"""
        try:
            with open(self.__link_state_path, 'r') as f:
                content = f.read().strip()
            
            if content in ["On","on"]:  # 连接状态
                return True
            else:
                return False
        except Exception as e:
            return False

    async def __monitor_link_state(self) -> None:
        prev_state = self.__connected_state
        
        while True:
            try:
                current_state = self.__read_link_state()
                if current_state != prev_state:
                    prev_state = current_state
                    self.__connected_state = current_state
                    await self.trigger_state()
                    get_logger(0).debug("Link state changed to: %s", current_state)
            except Exception as e:
                get_logger(0).debug("Error in polling link state: %s", e)
            
            await asyncio.sleep(1)  # 每秒检查一次

    async def get_state(self) -> dict:
        keyboard_state = await self.__keyboard_proc.get_state()
        if self.__touch_mode and self.__touch_proc:
            touch_state = await self.__touch_proc.get_state()
            mouse_state = {"online": touch_state.get("online", True), "absolute": True}
        elif self.__hybrid_mode:
            mouse_state = {**(await self.__mouse_abs.get_state()), "absolute": True}  # type: ignore
        else:
            mouse_state = await self.__mouse_current.get_state()
        return {
            "enabled": True,
            "online": True,
            "busy": False,
            "connected": self.__connected_state,  # 使用从 link_state 读取的连接状态
            "keyboard": {
                "online": keyboard_state["online"],
                "leds": {
                    "caps": keyboard_state["caps"],
                    "scroll": keyboard_state["scroll"],
                    "num": keyboard_state["num"],
                },
                "outputs": {"available": [], "active": ""},
            },
            "mouse": {
                "outputs": {
                    "available": self.__get_mouse_outputs_available(),
                    "active": self.__get_current_mouse_mode(),
                },
                **mouse_state,
            },
            **self._get_jiggler_state(),
        }

    async def trigger_state(self) -> None:
        self.__notifier.notify(1)

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        prev: dict = {}
        while True:
            if (await self.__notifier.wait()) > 0:
                prev = {}
            new = await self.get_state()
            if new != prev:
                prev = copy.deepcopy(new)
                yield new

    async def reset(self) -> None:
        self.__keyboard_proc.send_reset_event()
        self.__mouse_proc.send_reset_event()
        if self.__mouse_alt_proc:
            self.__mouse_alt_proc.send_reset_event()
        if self.__touch_proc:
            self.__touch_proc.send_reset_event()

    async def cleanup(self) -> None:
        try:
            self.__keyboard_proc.cleanup()
        finally:
            try:
                self.__mouse_proc.cleanup()
            finally:
                try:
                    if self.__mouse_alt_proc:
                        self.__mouse_alt_proc.cleanup()
                finally:
                    if self.__touch_proc:
                        self.__touch_proc.cleanup()

    # =====

    def set_params(
        self,
        keyboard_output: (str | None)=None,
        mouse_output: (str | None)=None,
        jiggler: (bool | None)=None,
    ) -> None:

        _ = keyboard_output
        changed = False
        if mouse_output == "usb_touch":
            if not self.__touch_proc:
                get_logger(0).warning("Touch mouse mode requires touch device")
            elif not self.__touch_mode:
                self.__clear_mouse_state()
                if self.__hybrid_mode:
                    self.__hybrid_mode = False
                    get_logger(0).info("HID mouse: left hybrid mode")
                self.__touch_mode = True
                self._set_jiggler_absolute(True)
                get_logger(0).info(
                    "HID mouse: entered touch mode (events -> usb_touch [%s])",
                    self.__touch_device_path or "?",
                )
                changed = True
        elif mouse_output == "usb_hybrid":
            if not self.__mouse_alt_proc or not self.__mouse_abs or not self.__mouse_rel:
                get_logger(0).warning("Hybrid mouse mode requires mouse_alt device")
            elif not self.__hybrid_mode:
                if self.__touch_mode:
                    self.__touch_mode = False
                    self.__clear_touch_state()
                    get_logger(0).info("HID mouse: left touch mode")
                self.__clear_mouse_state()
                self.__hybrid_mode = True
                self._set_jiggler_absolute(True)
                get_logger(0).info(
                    "HID mouse: entered hybrid mode (move -> %s [%s], button/wheel -> %s [%s])",
                    "usb", self.__mouse_device_paths.get("usb", "?"),
                    "usb_rel", self.__mouse_device_paths.get("usb_rel", "?"),
                )
                changed = True
        elif mouse_output in self.__mouses:
            if self.__hybrid_mode:
                self.__hybrid_mode = False
                self.__clear_mouse_state()
                get_logger(0).info("HID mouse: left hybrid mode")
                changed = True
            if self.__touch_mode:
                self.__touch_mode = False
                self.__clear_touch_state()
                get_logger(0).info("HID mouse: left touch mode")
                changed = True
            if mouse_output != self.__get_current_mouse_mode():
                self.__mouse_current.send_clear_event()
                self.__mouse_current = self.__mouses[mouse_output]
                self.__mouse_current.set_win98_fix(mouse_output == "usb_win98")
                self._set_jiggler_absolute(self.__mouse_current.is_absolute())
                changed = True
        if changed:
            self.__notifier.notify()
        if jiggler is not None:
            self._set_jiggler_active(jiggler)
            self.__notifier.notify()

    def _send_key_event(self, key: int, state: bool) -> None:
        self.__keyboard_proc.send_key_event(key, state)

    def _send_mouse_button_event(self, button: int, state: bool) -> None:
        if self.__touch_mode and self.__touch_proc:
            # Only left button translates to touch press/release;
            # right/middle/back/forward have no touchscreen equivalent.
            if button == ecodes.BTN_LEFT:
                self.__touch_sim_down = state
                get_logger(0).info(
                    "HID touch [button]: button=%d state=%s | device=%s",
                    button, state, self.__touch_device_path or "?",
                )
                self.__touch_proc.send_touch_event(self.__touch_sim_x, self.__touch_sim_y, state)
            else:
                get_logger(0).debug(
                    "HID touch [button]: dropped button=%d state=%s in touch mode",
                    button, state,
                )
            return
        proc = self.__get_hybrid_mouse_rel() if self.__hybrid_mode else self.__mouse_current
        proc.send_button_event(button, state)

    def _send_mouse_move_event(self, to_x: int, to_y: int) -> None:
        if self.__touch_mode and self.__touch_proc:
            self.__touch_sim_x = to_x
            self.__touch_sim_y = to_y
            get_logger(0).info(
                "HID touch [move]: to_x=%d to_y=%d touching=%s | device=%s",
                to_x, to_y, self.__touch_sim_down, self.__touch_device_path or "?",
            )
            self.__touch_proc.send_touch_event(to_x, to_y, self.__touch_sim_down)
            return
        proc = self.__get_hybrid_mouse_abs() if self.__hybrid_mode else self.__mouse_current
        proc.send_move_event(to_x, to_y)  # type: ignore

    def _send_mouse_relative_event(self, delta_x: int, delta_y: int) -> None:
        if self.__touch_mode:
            get_logger(0).debug(
                "HID touch [relative]: dropped in touch mode (delta_x=%d delta_y=%d)",
                delta_x, delta_y,
            )
            return
        if self.__hybrid_mode:
            get_logger(0).debug(
                "HID mouse [relative]: dropped in hybrid mode (delta_x=%d delta_y=%d)",
                delta_x, delta_y,
            )
            return
        self.__mouse_current.send_relative_event(delta_x, delta_y)

    def _send_mouse_wheel_event(self, delta_x: int, delta_y: int) -> None:
        if self.__touch_mode:
            get_logger(0).debug(
                "HID touch [wheel]: dropped in touch mode (delta_x=%d delta_y=%d)",
                delta_x, delta_y,
            )
            return
        proc = self.__get_hybrid_mouse_rel() if self.__hybrid_mode else self.__mouse_current
        proc.send_wheel_event(delta_x, delta_y)

    def _send_touch_event(self, to_x: int, to_y: int, touching: bool) -> None:
        # Real touch events from web UI always go to the touch HID,
        # independent of the current mouse_output mode.
        if not self.__touch_proc:
            get_logger(0).debug("HID touch [event]: dropped, no touch device")
            return
        get_logger(0).info(
            "HID touch [event]: to_x=%d to_y=%d touching=%s | device=%s",
            to_x, to_y, touching, self.__touch_device_path or "?",
        )
        self.__touch_proc.send_touch_event(to_x, to_y, touching)

    def __get_hybrid_mouse_abs(self) -> MouseProcess:
        assert self.__mouse_abs is not None
        return self.__mouse_abs

    def __get_hybrid_mouse_rel(self) -> MouseProcess:
        assert self.__mouse_rel is not None
        return self.__mouse_rel

    def _clear_events(self) -> None:
        self.__keyboard_proc.send_clear_event()
        self.__mouse_proc.send_clear_event()
        if self.__mouse_alt_proc:
            self.__mouse_alt_proc.send_clear_event()
        if self.__touch_proc:
            self.__touch_proc.send_clear_event()

    # =====

    def __clear_mouse_state(self) -> None:
        self.__mouse_proc.send_clear_event()
        if self.__mouse_alt_proc:
            self.__mouse_alt_proc.send_clear_event()

    def __clear_touch_state(self) -> None:
        self.__touch_sim_down = False
        if self.__touch_proc:
            self.__touch_proc.send_clear_event()

    def __get_mouse_outputs_available(self) -> list[str]:
        avail = list(self.__mouses.keys())
        if self.__mouse_alt_proc:
            avail.append("usb_hybrid")
        if self.__touch_proc:
            avail.append("usb_touch")
        return avail

    def __get_current_mouse_mode(self) -> str:
        if self.__touch_mode:
            return "usb_touch"
        if self.__hybrid_mode:
            return "usb_hybrid"
        if len(self.__mouses) == 0:
            return ""
        if self.__mouse_current.is_absolute():
            return ("usb_win98" if self.__mouse_current.get_win98_fix() else "usb")
        return "usb_rel"
