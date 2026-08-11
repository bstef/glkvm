# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
# ========================================================================== #


import asyncio
import os


_HID_SUSPEND_FILE = "/var/run/kvmd-hid-otg.suspend"
_HID_DEVICE_NAMES = frozenset(("hidg0", "hidg1", "hidg2", "hidg3"))


def _get_hid_fd_holders() -> list[str]:
    holders: list[str] = []
    for proc_name in os.listdir("/proc"):
        if not proc_name.isdigit():
            continue

        proc_path = os.path.join("/proc", proc_name)
        try:
            with open(os.path.join(proc_path, "comm")) as comm_file:
                comm = comm_file.read().strip()
            fd_names = os.listdir(os.path.join(proc_path, "fd"))
        except OSError:
            continue

        for fd_name in fd_names:
            fd_path = os.path.join(proc_path, "fd", fd_name)
            try:
                target = os.readlink(fd_path).removesuffix(" (deleted)")
            except OSError:
                continue
            if os.path.dirname(target) == "/dev" and os.path.basename(target) in _HID_DEVICE_NAMES:
                holders.append(f"{proc_name}/{comm}:{fd_name}->{target}")
    return holders


async def suspend_hid_otg(logger, reason: str, timeout: float = 3.0) -> None:
    logger.info("%s: suspending HID", reason)
    with open(_HID_SUSPEND_FILE, "w"):
        pass

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        while True:
            holders = _get_hid_fd_holders()
            if not holders:
                logger.info("%s: HID fds released", reason)
                return
            if loop.time() >= deadline:
                raise RuntimeError(f"{reason}: timeout waiting HID fds released: {holders}")
            logger.info("%s: waiting HID fds released: %s", reason, holders)
            await asyncio.sleep(0.1)
    except Exception:
        resume_hid_otg(logger, reason)
        raise


def resume_hid_otg(logger, reason: str) -> None:
    try:
        os.unlink(_HID_SUSPEND_FILE)
    except FileNotFoundError:
        pass
    logger.info("%s: resumed HID", reason)
