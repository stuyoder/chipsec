# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018 - 2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
Displays CPU information

Usage:
    ``chipsec_main -m common.cpu.arm_cpu_info``

Examples:
    >>> chipsec_main.py -m common.cpu.arm_cpu_info

.. note:
    No PASS/FAIL returned, INFORMATION only.

"""

import struct
import os
from chipsec.module_common import BaseModule, ModuleResult
from chipsec.defines import bytestostring

cpu_implementer_lookup = {
    "0x41": "Arm"
}

arm_cpu_type_lookup = {
    "0xd07": "A57",
    "0xd08": "A72",
    "0xd03": "A53",
    "0xd09": "A73",
    "0xd0a": "A75",
    "0xd04": "A35",
    "0xd05": "A55",
    "0xd0b": "A76",
    "0xd0c": "N1",
    "0xd0d": "A77",
    "0xd40": "V1",
    "0xd41": "A78",
    "0xd42": "A78AE",
    "0xd44": "X1",
    "0xd46": "A510",
    "0xd47": "A710",
    "0xd48": "X2",
    "0xd49": "N2",
    "0xd4B": "A78C"
}

class arm_cpu_info(BaseModule):
    def __init__(self):
        super(arm_cpu_info, self).__init__()

    def is_supported(self):
        return True

    def run(self, module_argv):
        # Log the start of the test
        self.logger.start_test('Current Processor Information:')
        self.res = ModuleResult.INFORMATION

        filePath = "/proc/cpuinfo"

        cpuinfo = open(filePath, 'r').read()

        cpu_implementer = get_cpu_implementer(cpuinfo)
        cpu = get_cpu_type(cpuinfo)
        cpu_type_lookup = get_cpu_type_lookup(cpu_implementer)
        arch = get_cpu_architecture(cpuinfo)
        variant = get_cpu_variant(cpuinfo)
        revision = get_cpu_revision(cpuinfo)

        cpu_str = cpu_implementer_lookup[cpu_implementer] + " " + cpu_type_lookup[cpu]
        self.logger.log('[*] CPU: {}'.format(cpu_str))
        self.logger.log('[*]         Architecture Version: Armv{}'.format(arch))
        self.logger.log('[*]                      Variant: {}'.format(variant))
        self.logger.log('[*]                     Revision: {}'.format(revision))

        self.logger.log_information('Processor information displayed')

        return self.res

def get_cpu_implementer(cpuinfo):

    lines = cpuinfo.split(os.linesep)

    for line in lines:
        if (line.find("CPU implementer") != -1):
            array = line.split(":")
            cpu_implementer = array[1].strip()
            break

    return cpu_implementer

def get_cpu_type_lookup(cpu):
    if (cpu == "0x41"):
        return arm_cpu_type_lookup

def get_cpu_type(cpuinfo):

    lines = cpuinfo.split(os.linesep)

    for line in lines:
        if (line.find("CPU part") != -1):
            array = line.split(":")
            cpu_type = array[1].strip()
            break

    return cpu_type

def get_cpu_revision(cpuinfo):

    lines = cpuinfo.split(os.linesep)

    for line in lines:
        if (line.find("CPU revision") != -1):
            array = line.split(":")
            cpu_revision = array[1].strip()
            break

    return cpu_revision

def get_cpu_variant(cpuinfo):

    lines = cpuinfo.split(os.linesep)

    for line in lines:
        if (line.find("CPU variant") != -1):
            array = line.split(":")
            cpu_variant = array[1].strip()
            break

    return cpu_variant

def get_cpu_architecture(cpuinfo):

    lines = cpuinfo.split(os.linesep)

    for line in lines:
        if (line.find("CPU architecture") != -1):
            array = line.split(":")
            cpu_architecture = array[1].strip()
            break

    return cpu_architecture
