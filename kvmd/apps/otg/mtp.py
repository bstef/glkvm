# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
# ========================================================================== #


import os
import subprocess
import time


_MOUNT_PATH = "/dev/ffs-mtp"
_STORAGE_PATH = "/userdata/media"
_DAEMON_PATH = "/usr/bin/umtprd"


def prepare(timeout: float) -> None:
    os.makedirs(_STORAGE_PATH, exist_ok=True)
    os.makedirs(_MOUNT_PATH, exist_ok=True)
    if not _is_mounted():
        subprocess.run(["mount", "-t", "functionfs", "mtp", _MOUNT_PATH], check=True)
    try:
        subprocess.run([
            "start-stop-daemon", "--start", "--quiet", "--oknodo", "--background",
            "--exec", _DAEMON_PATH,
        ], check=True)
        deadline = time.monotonic() + timeout
        endpoints = [os.path.join(_MOUNT_PATH, f"ep{index}") for index in range(1, 4)]
        while not all(os.path.exists(path) for path in endpoints):
            if time.monotonic() >= deadline:
                raise RuntimeError("uMTPrd did not create FunctionFS endpoints")
            time.sleep(0.05)
    except Exception:
        cleanup()
        raise


def cleanup() -> None:
    subprocess.run([
        "start-stop-daemon", "--stop", "--quiet", "--oknodo", "--signal", "TERM",
        "--exec", _DAEMON_PATH,
    ], check=True)
    deadline = time.monotonic() + 3
    while subprocess.run([
        "pidof", os.path.basename(_DAEMON_PATH),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            raise RuntimeError("uMTPrd did not stop")
        time.sleep(0.05)
    if _is_mounted():
        subprocess.run(["umount", _MOUNT_PATH], check=True)


def _is_mounted() -> bool:
    with open("/proc/mounts") as file:
        return any(line.split()[1] == _MOUNT_PATH for line in file if len(line.split()) >= 2)
