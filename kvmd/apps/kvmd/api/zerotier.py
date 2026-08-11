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
import subprocess
from typing import Dict, Optional
import json
import os
import re

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger
from .common import is_process_running, read_json_file, run_command, update_json_file

logger = get_logger()


class ZerotierApi:
    __config_path = "/etc/kvmd/user/zerotier.json"
    
    def __init__(self) -> None:
        self._logger = logger

    async def _run_command(self, cmd: str, timeout: float = 30.0) -> str:
        return await run_command(cmd, logger=self._logger, timeout=timeout)

    async def _check_zerotierd_process(self) -> bool:
        return await is_process_running(["pgrep", "-f", "zerotier-one"], logger=self._logger, error_label="zerotierd process")

    async def _read_config_file(self) -> Dict:
        return await read_json_file(self.__config_path, {"enable": False, "token": ""}, logger=self._logger)

    async def _update_config_file(self, enable: Optional[bool] = None, token: Optional[str] = None) -> None:
        config = await update_json_file(
            self.__config_path,
            {"enable": False, "token": ""},
            {"enable": enable, "token": token},
            logger=self._logger,
        )
        self._logger.info(f"Updated zerotier config file: enable={config.get('enable')}")

    async def _parse_listnetworks(self) -> Optional[Dict]:
        """
        解析 zerotier-cli listnetworks 命令输出（JSON格式）
        返回网络信息字典，如果没有网络则返回None
        """
        try:
            process = await asyncio.create_subprocess_exec(
                "zerotier-cli", "-j", "listnetworks",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self._logger.error(f"zerotier-cli listnetworks failed: {stderr.decode()}")
                return None

            output = stdout.decode().strip()

            # 解析JSON输出
            networks = json.loads(output)

            # 如果没有网络，返回None
            if not networks or len(networks) == 0:
                return None

            # 返回第一个网络的信息
            network = networks[0]
            return {
                "nwid": network.get("nwid", ""),
                "name": network.get("name", ""),
                "mac": network.get("mac", ""),
                "status": network.get("status", ""),
                "type": network.get("type", ""),
                "dev": network.get("portDeviceName", ""),
                "ips": network.get("assignedAddresses", [])
            }

        except json.JSONDecodeError as e:
            self._logger.error(f"Error parsing zerotier JSON output: {e}")
            return None
        except Exception as e:
            self._logger.error(f"Error parsing zerotier listnetworks: {e}")
            return None
    
    async def _leave_all_networks(self) -> None:
        """
        断开所有已连接的 ZeroTier 网络
        通过停止服务、删除数据目录并重启服务来实现
        """
        try:
            self._logger.info("Leaving all networks by resetting ZeroTier service")

            # 1. 停止 ZeroTier 服务
            try:
                process = await asyncio.create_subprocess_shell(
                    "/etc/init.d/S99zerotier stop",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Stop ZeroTier service failed: {stderr.decode()}")
                else:
                    self._logger.info(f"ZeroTier service stopped: {stdout.decode().strip()}")
            except Exception as e:
                self._logger.error(f"Error stopping ZeroTier service: {e}")

            # 等待服务完全停止
            await asyncio.sleep(1)

            # 2. 删除 ZeroTier 用户数据目录
            try:
                process = await asyncio.create_subprocess_shell(
                    "rm -rf /etc/kvmd/user/zerotier",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Remove ZeroTier data directory failed: {stderr.decode()}")
                else:
                    self._logger.info("ZeroTier data directory removed")
            except Exception as e:
                self._logger.error(f"Error removing ZeroTier data directory: {e}")

            # 3. 重启 ZeroTier 服务
            try:
                process = await asyncio.create_subprocess_shell(
                    "/etc/init.d/S99zerotier start",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self._logger.warning(f"Start ZeroTier service failed: {stderr.decode()}")
                else:
                    self._logger.info(f"ZeroTier service started: {stdout.decode().strip()}")
            except Exception as e:
                self._logger.error(f"Error starting ZeroTier service: {e}")

            # 等待服务完全启动
            await asyncio.sleep(4)

            self._logger.info("Network reset completed")

        except Exception as e:
            self._logger.error(f"Error leaving networks: {e}")

    @exposed_http("GET", "/zerotier/status")
    async def _status_handler(self, _: Request) -> Response:
        """
        获取 zerotier 服务状态
        通过 zerotier-cli listnetworks 获取详细的网络状态
        """
        try:
            # 读取配置文件获取启动状态
            config = await self._read_config_file()
            enabled = config.get("enable", False)

            # 检查进程状态
            process_running = await self._check_zerotierd_process()

            # 获取网络详细信息
            network_info = None
            if process_running:
                network_info = await self._parse_listnetworks()

            response_data = {
                "enabled": enabled,
                "process_running": process_running
            }

            # 如果有网络信息，添加详细状态
            if network_info:
                response_data.update({
                    "nwid": network_info["nwid"],
                    "name": network_info["name"],
                    "status": network_info["status"],
                    "dev": network_info["dev"],
                    "ips": network_info["ips"]
                })

            return make_json_response(response_data)
        except Exception as e:
            self._logger.error(f"Error checking zerotier status: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET", "/zerotier/gui_status",allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_status_handler(self,request:Request) -> Response:
        return await self._status_handler(request)

    @exposed_http("POST", "/zerotier/start")
    async def _start_handler(self, _: Request) -> Response:
        """
        启动 zerotier 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=True)
            
            # 启动服务
            cmd = "/etc/init.d/S99zerotier start"
            output = await self._run_command(cmd)
            
            # 等待服务启动
            await asyncio.sleep(2)
            
            # 检查服务是否真的启动了
            process_running = await self._check_zerotierd_process()
            
            return make_json_response({
                "success": process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error starting zerotier service: {e}")
            await self._update_config_file(enable=False)
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST","/zerotier/gui_start",allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_start_handler(self,request:Request) ->Response:
        return await self._start_handler(request)


    @exposed_http("POST", "/zerotier/stop")
    async def _stop_handler(self, _: Request) -> Response:
        """
        停止 zerotier 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=False)
            
            # 停止服务
            cmd = "/etc/init.d/S99zerotier stop"
            output = await self._run_command(cmd)
            
            # 等待服务停止
            await asyncio.sleep(2)
            
            # 检查服务是否真的停止了
            process_running = await self._check_zerotierd_process()
            
            return make_json_response({
                "success": not process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error stopping zerotier service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/zerotier/gui_stop",allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_stop_handler(self,request:Request) ->Response:
        return await self._stop_handler(request)

    @exposed_http("POST", "/zerotier/set_token")
    async def _set_token_handler(self, request: Request) -> Response:
        """
        设置 zerotier token
        接受参数：
        - token: 字符串，zerotier token（仅允许大小写字母和数字）
        """
        try:
            # 从请求中获取token参数
            token = request.query.get("token", None)

            # 检查token参数
            if token is None:
                return make_json_exception(BadRequestError("Token parameter is required"), 400)

            # Token 注入检测：只允许大小写字母和数字，防止命令注入攻击
            if not re.match(r'^[a-zA-Z0-9]+$', token):
                self._logger.warning(f"Invalid token format detected, possible injection attempt: {token}")
                return make_json_exception(
                    BadRequestError("Invalid token format. Only alphanumeric characters (a-z, A-Z, 0-9) are allowed."),
                    400
                )

            # 检查token长度（ZeroTier网络ID通常是16位十六进制）
            if len(token) < 8 or len(token) > 32:
                self._logger.warning(f"Token length out of acceptable range: {len(token)}")
                return make_json_exception(
                    BadRequestError("Invalid token length. Token must be between 8 and 32 characters."),
                    400
                )

            # 在设置新token之前，先断开所有已连接的网络
            self._logger.info("Leaving all existing networks before setting new token")
            await self._leave_all_networks()

            # 调用zerotier-cli join命令，最多重试3次
            max_retries = 3
            retry_delay = 1  # 秒

            for attempt in range(1, max_retries + 1):
                try:
                    join_cmd = f"zerotier-cli join {token}"
                    join_output = await self._run_command(join_cmd)
                    self._logger.info(f"Zerotier join command executed successfully on attempt {attempt}: {join_output}")

                    # 不再需要更新配置文件中的token
                    # await self._update_config_file(token=token)

                    return make_json_response({
                        "success": True,
                        "message": "Token updated successfully",
                        "join_output": join_output,
                        "attempts": attempt
                    })
                except Exception as join_error:
                    self._logger.warning(f"Zerotier join attempt {attempt}/{max_retries} failed: {join_error}")

                    if attempt < max_retries:
                        # 如果不是最后一次尝试，等待1秒后重试
                        self._logger.info(f"Retrying in {retry_delay} second(s)...")
                        await asyncio.sleep(retry_delay)
                    else:
                        # 最后一次尝试也失败了，返回错误
                        self._logger.error(f"All {max_retries} join attempts failed")
                        return make_json_exception(BadRequestError(f"Join command failed after {max_retries} attempts: {join_error}"), 502)

        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting zerotier token: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST","/zerotier/gui_set_token",allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_set_token_handler(self,request:Request)->Response:
        return await self._set_token_handler(request)

    @exposed_http("POST", "/zerotier/leave")
    async def _leave_handler(self, request: Request) -> Response:
        """
        离开 ZeroTier 网络

        可选 query 参数：
        - nwid: 网络 ID；省略时使用当前已加入的网络
        - reset: 为 true/1/yes 时执行完整重置（停止服务、清除数据目录并重启）
        """
        try:
            reset = request.query.get("reset", "").lower() in ("1", "true", "yes")

            if reset:
                await self._leave_all_networks()
                process_running = await self._check_zerotierd_process()
                network_info = await self._parse_listnetworks() if process_running else None
                return make_json_response({
                    "success": True,
                    "message": "All networks left and ZeroTier data reset",
                    "left": True,
                    "reset": True,
                    "process_running": process_running,
                    "network_connected": network_info is not None,
                })

            process_running = await self._check_zerotierd_process()
            if not process_running:
                return make_json_response({
                    "success": True,
                    "message": "ZeroTier service is not running",
                    "left": False,
                    "process_running": False,
                })

            nwid = request.query.get("nwid")
            if nwid is None:
                network_info = await self._parse_listnetworks()
                if not network_info:
                    return make_json_response({
                        "success": True,
                        "message": "No network to leave",
                        "left": False,
                        "process_running": True,
                    })
                nwid = network_info["nwid"]

            if not re.match(r"^[a-fA-F0-9]{16}$", nwid):
                return make_json_exception(
                    BadRequestError("Invalid network ID format. Network ID must be a 16-character hexadecimal string."),
                    400,
                )

            leave_output = await self._run_command(
                f"zerotier-cli leave {nwid}",
                timeout=15.0,
            )

            network_info = await self._parse_listnetworks()
            return make_json_response({
                "success": True,
                "message": "Left network successfully",
                "nwid": nwid,
                "leave_output": leave_output,
                "left": True,
                "process_running": True,
                "network_connected": network_info is not None,
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error leaving zerotier network: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/zerotier/gui_leave", allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_leave_handler(self, request: Request) -> Response:
        return await self._leave_handler(request)

    @exposed_http("GET", "/zerotier/auth")
    async def _auth_handler(self, request: Request) -> Response:
        """
        获取 ZeroTier Central 首页 URL
        """
        try:
            _ = request
            auth_url = "https://central.zerotier.com/"

            return make_json_response({
                "success": True,
                "auth_url": auth_url
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error building zerotier auth url: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("GET","/zerotier/gui_auth",allowed_exe_paths=["/usr/sbin/gl_kvm_gui"])
    async def _gui_auth_handler(self,request:Request)->Response:
        return await self._auth_handler(request)
