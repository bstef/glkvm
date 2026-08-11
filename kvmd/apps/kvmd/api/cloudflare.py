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
from typing import Dict, Optional

from aiohttp.web import Request, Response

from ....htserver import (
    BadRequestError,
    exposed_http,
    make_json_response,
    make_json_exception,
)
from ....logging import get_logger
from .common import is_process_running, run_command, update_json_file, read_json_file

logger = get_logger()


class CloudflareApi:
    __config_path = "/etc/kvmd/user/cloudflare.json"
    
    def __init__(self) -> None:
        self._logger = logger

    async def _run_command(self, cmd: str) -> str:
        return await run_command(cmd, logger=self._logger)

    async def _check_cloudflared_process(self) -> bool:
        return await is_process_running(["pgrep", "-f", "cloudflared"], logger=self._logger, error_label="cloudflared process")

    async def _read_config_file(self) -> Dict:
        return await read_json_file(self.__config_path, {"enable": False, "token": ""}, logger=self._logger)

    async def _update_config_file(self, enable: Optional[bool] = None, token: Optional[str] = None) -> None:
        config = await update_json_file(
            self.__config_path,
            {"enable": False, "token": ""},
            {"enable": enable, "token": token},
            logger=self._logger,
        )
        self._logger.info(f"Updated Cloudflare config file: enable={config.get('enable')}, token_set={bool(config.get('token'))}")

    @exposed_http("GET", "/cloudflare/status")
    async def _status_handler(self, _: Request) -> Response:
        """
        获取 Cloudflare 服务状态
        返回启动状态和进程状态
        """
        try:
            # 读取配置文件获取启动状态
            config = await self._read_config_file()
            enabled = config.get("enable", False)
            
            # 检查进程状态
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "enabled": enabled,
                "process_running": process_running,
                "token_set": bool(config.get("token"))
            })
        except Exception as e:
            self._logger.error(f"Error checking Cloudflare status: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/start")
    async def _start_handler(self, _: Request) -> Response:
        """
        启动 Cloudflare 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=True)
            
            # 启动服务
            cmd = "/etc/init.d/S99cloudflare start"
            output = await self._run_command(cmd)
            
            # 等待服务启动
            await asyncio.sleep(2)
            
            # 检查服务是否真的启动了
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error starting Cloudflare service: {e}")
            await self._update_config_file(enable=False)
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/stop")
    async def _stop_handler(self, _: Request) -> Response:
        """
        停止 Cloudflare 服务
        """
        try:
            # 更新配置文件
            await self._update_config_file(enable=False)
            
            # 停止服务
            cmd = "/etc/init.d/S99cloudflare stop"
            output = await self._run_command(cmd)
            
            # 等待服务停止
            await asyncio.sleep(2)
            
            # 检查服务是否真的停止了
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": not process_running,
                "output": output,
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error stopping Cloudflare service: {e}")
            return make_json_exception(BadRequestError(), 502)

    @exposed_http("POST", "/cloudflare/set_token")
    async def _set_token_handler(self, request: Request) -> Response:
        """
        设置 Cloudflare token
        接受参数：
        - token: 字符串，Cloudflare token
        """
        try:
            # 从请求中获取token参数
            token = request.query.get("token", None)
            
            # 检查token参数
            if token is None:
                return make_json_response({
                    "success": False,
                    "error": "Token parameter is required"
                })
            
            # 更新配置文件中的token
            await self._update_config_file(token=token)
            
            # 重启Cloudflare服务以应用新的token
            cmd = "/etc/init.d/S99cloudflare restart"
            output = await self._run_command(cmd)
            
            # 检查服务是否正常运行
            process_running = await self._check_cloudflared_process()
            
            return make_json_response({
                "success": True,
                "message": "Token updated successfully",
                "process_running": process_running
            })
        except BadRequestError as e:
            return make_json_exception(e, 400)
        except Exception as e:
            self._logger.error(f"Error setting Cloudflare token: {e}")
            return make_json_exception(BadRequestError(), 502) 