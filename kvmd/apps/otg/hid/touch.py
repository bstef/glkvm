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


from . import Hid


# =====
def make_touch_hid() -> Hid:
    return Hid(
        protocol=0,  # None protocol
        subclass=0,  # No subclass

        # 1 byte flags (Tip Switch + In Range + 6 padding bits) + 2x uint16 coords
        report_length=5,

        report_descriptor=bytes([
            # Single-touch digitizer (Touch Screen). Hosts (Android/iOS/Win/Linux)
            # interpret press/move/release as real touch events.
            0x05, 0x0D,  # USAGE_PAGE (Digitizers)
            0x09, 0x04,  # USAGE (Touch Screen)
            0xA1, 0x01,  # COLLECTION (Application)

            0x09, 0x22,  # USAGE (Finger)
            0xA1, 0x02,  # COLLECTION (Logical)

            # Tip switch + In Range, 1 bit each
            0x09, 0x42,  # USAGE (Tip Switch)
            0x09, 0x32,  # USAGE (In Range)
            0x15, 0x00,  # LOGICAL_MINIMUM (0)
            0x25, 0x01,  # LOGICAL_MAXIMUM (1)
            0x95, 0x02,  # REPORT_COUNT (2)
            0x75, 0x01,  # REPORT_SIZE (1)
            0x81, 0x02,  # INPUT (Data,Var,Abs)

            # Padding (6 bits) to align to a byte
            0x95, 0x06,  # REPORT_COUNT (6)
            0x81, 0x03,  # INPUT (Const,Var,Abs)

            # X, Y (uint16, 0..32767)
            0x05, 0x01,  # USAGE_PAGE (Generic Desktop)
            0x09, 0x30,  # USAGE (X)
            0x09, 0x31,  # USAGE (Y)
            0x16, 0x00, 0x00,  # LOGICAL_MINIMUM (0)
            0x26, 0xFF, 0x7F,  # LOGICAL_MAXIMUM (32767)
            0x75, 0x10,  # REPORT_SIZE (16)
            0x95, 0x02,  # REPORT_COUNT (2)
            0x81, 0x02,  # INPUT (Data,Var,Abs)

            0xC0,  # END_COLLECTION (Logical)
            0xC0,  # END_COLLECTION
        ]),
    )
