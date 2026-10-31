"""Everything SecretBroker does differently on each operating system, behind one interface.

    from secretbroker import platform
    platform.protect_for_service(key, entropy, data_dir)

The rest of the code never checks sys.platform for these: it calls the functions below, which come from
windows.py, linux.py or macos.py. `INTERFACE` lists them; every platform module defines all of them
(tests/test_platform.py checks it), raising NotImplementedError where a port is not finished yet.

Note: inside this package, `import platform` would find this package only with a relative import
(`from . import platform`); the standard library's `platform` module is unaffected.
"""

import sys

from ._common import INTERFACE, InstallCancelled, ProtectError  # noqa: F401

if sys.platform == "win32":
    from .windows import *  # noqa: F401,F403
elif sys.platform == "darwin":
    from .macos import *  # noqa: F401,F403
else:
    from .linux import *  # noqa: F401,F403
