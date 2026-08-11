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


from typing import Generator
from typing import Any

from ....logging import get_logger

from .device import BaseDeviceProcess

from .events import BaseEvent
from .events import ClearEvent
from .events import ResetEvent
from .events import TouchEvent
from .events import make_touch_report


_FLAG_TIP_SWITCH = 0x01
_FLAG_IN_RANGE = 0x02


# =====
class TouchProcess(BaseDeviceProcess):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(
            name="touch",
            read_size=0,
            initial_state={},
            **kwargs,
        )
        self.__x = 0
        self.__y = 0
        self.__touching = False
        self.__in_range = False

    def cleanup(self) -> None:
        self._stop()
        get_logger().info("Clearing HID-touch events ...")
        self.__touching = False
        self.__in_range = False
        self._cleanup_write(make_touch_report(0, self.__x, self.__y))

    def send_clear_event(self) -> None:
        self._clear_queue()
        self._queue_event(ClearEvent())

    def send_reset_event(self) -> None:
        self._clear_queue()
        self._queue_event(ResetEvent())

    def send_touch_event(self, to_x: int, to_y: int, touching: bool) -> None:
        self._queue_event(TouchEvent(to_x, to_y, touching))

    # =====

    def _process_event(self, event: BaseEvent) -> Generator[bytes, None, None]:
        if isinstance(event, (ClearEvent, ResetEvent)):
            self.__touching = False
            self.__in_range = False
            yield self.__make_report()
        elif isinstance(event, TouchEvent):
            yield from self.__process_touch_event(event)
        else:
            raise RuntimeError(f"Not implemented event: {event}")

    def __process_touch_event(self, event: TouchEvent) -> Generator[bytes, None, None]:
        self.__x = event.to_fixed_x
        self.__y = event.to_fixed_y
        if event.touching:
            self.__touching = True
            self.__in_range = True
            yield self.__make_report()
        else:
            # Release: first drop tip switch (still in range), then drop in range
            self.__touching = False
            yield self.__make_report()
            self.__in_range = False
            yield self.__make_report()

    def __make_report(self) -> bytes:
        flags = 0
        if self.__touching:
            flags |= _FLAG_TIP_SWITCH
        if self.__in_range:
            flags |= _FLAG_IN_RANGE
        return make_touch_report(flags, self.__x, self.__y)
