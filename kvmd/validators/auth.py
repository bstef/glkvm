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


import re

from typing import Any

from .basic import valid_string_list
from .basic import valid_number
from .basic import valid_bool

from . import check_re_match
from . import raise_error


# =====
def valid_user(arg: Any) -> str:
    return check_re_match(arg, "username characters", r"^[a-z_][a-z0-9_-]*$")


def valid_users_list(arg: Any) -> list[str]:
    return valid_string_list(arg, subval=valid_user, name="users list")


def valid_passwd(arg: Any) -> str:
    return check_re_match(arg, "passwd characters", r"^[\x20-\x7e]{5,63}\Z$", strip=False, hide=True)


# 强密码校验:用于"初始化密码"和"修改密码的新密码",不用于登录(登录仍用 valid_passwd,
# 以保证已有不符合此规则的旧密码依然可以登录)。
# 规则:长度 10~63,仅可打印 ASCII;大写字母、小写字母、数字、特殊字符四类中至少包含两类。
def valid_new_passwd(arg: Any) -> str:
    passwd = check_re_match(arg, "passwd characters", r"^[\x20-\x7e]{10,63}\Z$", strip=False, hide=True)
    categories = (
        bool(re.search(r"[A-Z]", passwd))
        + bool(re.search(r"[a-z]", passwd))
        + bool(re.search(r"[0-9]", passwd))
        + bool(re.search(r"[^A-Za-z0-9]", passwd))
    )
    if categories < 2:
        raise_error(passwd, "passwd complexity", hide=True)
    return passwd


def valid_expire(arg: Any) -> int:
    return int(valid_number(arg, min=0, name="expiration time"))


def valid_auth_token(arg: Any) -> str:
    return check_re_match(arg, "auth token", r"^[0-9a-f]{64}$", hide=True)


def valid_rate_limit_max_attempts(arg: Any) -> int:
    return int(valid_number(arg, min=1, max=100, name="rate limit max attempts"))


def valid_rate_limit_time_window(arg: Any) -> int:
    return int(valid_number(arg, min=60, max=3600, name="rate limit time window"))


def valid_rate_limit_lockout_duration(arg: Any) -> int:
    return int(valid_number(arg, min=60, max=3600, name="rate limit lockout duration"))
