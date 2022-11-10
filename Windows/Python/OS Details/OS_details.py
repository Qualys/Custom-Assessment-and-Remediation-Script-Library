import os
import sys
import platform
import sysconfig
print("os.name                     ", platform.platform())
print("sys.platform                ", sys.platform)
print("platform.system()           ", platform.system())
print("sysconfig.get_platform()    ", sysconfig.get_platform())
print("platform.machine()          ", platform.machine())
print("platform.architecture()     ", platform.architecture())
