# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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
Main UEFI component using platform specific and common UEFI functionality
"""

import struct
import os

from collections import namedtuple
import collections

from chipsec.hal import hal_base, mmio, spi, uefi_platform
from chipsec.hal.uefi_common import EFI_VENDOR_TABLE, EFI_VENDOR_TABLE_SIZE, EFI_VENDOR_TABLE_FORMAT, EFI_TABLE_HEADER_SIZE, EFI_TABLE_HEADER, EFI_TABLES, MAX_EFI_TABLE_SIZE
from chipsec.hal.uefi_common import S3BootScriptOpcode, S3_BOOTSCRIPT_VARIABLES, parse_efivar_file, EFI_REVISIONS, AUTH_SIG_VAR, ESAL_SIG_VAR
from chipsec.hal.uefi_common import EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_APPEND_WRITE, EFI_VARIABLE_NON_VOLATILE
from chipsec.hal.uefi_common import EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS, EFI_VARIABLE_HARDWARE_ERROR_RECORD, SECURE_BOOT_SIG_VAR
from chipsec.hal.uefi_common import IS_VARIABLE_ATTRIBUTE, EFI_TABLE_HEADER_FMT, EFI_SYSTEM_TABLE_SIGNATURE, EFI_RUNTIME_SERVICES_SIGNATURE, EFI_BOOT_SERVICES_SIGNATURE
from chipsec.hal.uefi_common import EFI_DXE_SERVICES_TABLE_SIGNATURE, EFI_CONFIGURATION_TABLE, ACPI_VARIABLE_SET_STRUCT_SIZE
from chipsec.logger import logger, print_buffer
from chipsec.file import write_file, read_file
from chipsec.defines import COMPRESSION_TYPES
from chipsec.defines import bytestostring
from chipsec.helper.oshelper import OsHelperError


########################################################################################################
#
# S3 Resume Boot-Script Parsing Functionality
#
########################################################################################################

def parse_script(script, log_script=False):
    off = 0
    entry_type = 0
    s3_boot_script_entries = []
    len_s = len(script)

    if log_script:
        logger().log('[uefi] +++ S3 Resume Boot-Script +++\n')
    script_type, script_header_length = uefi_platform.id_s3bootscript_type(script, log_script)
    off += script_header_length

    while (off < len_s) and (entry_type != S3BootScriptOpcode.EFI_BOOT_SCRIPT_TERMINATE_OPCODE):
        entry_type, s3script_entry = uefi_platform.parse_s3bootscript_entry(script_type, script, off, log_script)
        # couldn't parse the next entry - return what has been parsed so far
        if s3script_entry is None:
            return s3_boot_script_entries
        s3_boot_script_entries.append(s3script_entry)
        off += s3script_entry.length

    if log_script:
        logger().log('[uefi] +++ End of S3 Resume Boot-Script +++')

    if logger().HAL:
        logger().log('[uefi] S3 Resume Boot-Script size: 0x{:X}'.format(off))
    if logger().HAL:
        logger().log('\n[uefi] [++++++++++ S3 Resume Boot-Script Buffer ++++++++++]')
        print_buffer(bytestostring(script[: off]))

    return s3_boot_script_entries


########################################################################################################
#
# UEFI Variables Parsing Functionality
#
########################################################################################################


EFI_VAR_NAME_PK = 'PK'
EFI_VAR_NAME_KEK = 'KEK'
EFI_VAR_NAME_db = 'db'
EFI_VAR_NAME_dbx = 'dbx'
EFI_VAR_NAME_SecureBoot = 'SecureBoot'
EFI_VAR_NAME_SetupMode = 'SetupMode'
EFI_VAR_NAME_CustomMode = 'CustomMode'
EFI_VAR_NAME_SignatureSupport = 'SignatureSupport'
EFI_VAR_NAME_certdb = 'certdb'
EFI_VAR_NAME_AuthVarKeyDatabase = 'AuthVarKeyDatabase'

#
# \MdePkg\Include\Guid\ImageAuthentication.h
#
# define EFI_IMAGE_SECURITY_DATABASE_GUID \
#  { \
#    0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } \
#  }
#
# \MdePkg\Include\Guid\GlobalVariable.h
#
# define EFI_GLOBAL_VARIABLE \
#  { \
#    0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } \
#  }
#
EFI_GLOBAL_VARIABLE_GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
EFI_IMAGE_SECURITY_DATABASE_GUID = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
#EFI_VAR_GUID_SecureBoot = EFI_GLOBAL_VARIABLE
#EFI_VAR_GUID_db         = EFI_IMAGE_SECURITY_DATABASE_GUID

EFI_VARIABLE_DICT = {
    EFI_VAR_NAME_PK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_KEK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_db: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_dbx: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_SecureBoot: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SetupMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_CustomMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SignatureSupport: EFI_GLOBAL_VARIABLE_GUID

}


SECURE_BOOT_KEY_VARIABLES = (EFI_VAR_NAME_PK, EFI_VAR_NAME_KEK, EFI_VAR_NAME_db, EFI_VAR_NAME_dbx)
SECURE_BOOT_VARIABLES = (EFI_VAR_NAME_SecureBoot, EFI_VAR_NAME_SetupMode) + SECURE_BOOT_KEY_VARIABLES
SECURE_BOOT_VARIABLES_ALL = (EFI_VAR_NAME_CustomMode, EFI_VAR_NAME_SignatureSupport) + SECURE_BOOT_VARIABLES
AUTHENTICATED_VARIABLES = (EFI_VAR_NAME_AuthVarKeyDatabase, EFI_VAR_NAME_certdb) + SECURE_BOOT_KEY_VARIABLES


def get_auth_attr_string(attr):
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = attr_str + 'AW+'
    return attr_str[:-1].lstrip()


def get_attr_string(attr):
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_NON_VOLATILE):
        attr_str = attr_str + 'NV+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_BOOTSERVICE_ACCESS):
        attr_str = attr_str + 'BS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_RUNTIME_ACCESS):
        attr_str = attr_str + 'RT+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_HARDWARE_ERROR_RECORD):
        attr_str = attr_str + 'HER+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = attr_str + 'AW+'
    return attr_str[:-1].lstrip()


def print_efi_variable(offset, efi_var_buf, EFI_var_header, efi_var_name, efi_var_data, efi_var_guid, efi_var_attributes):
    logger().log('\n--------------------------------')
    logger().log('EFI Variable (offset = 0x{:X}):'.format(offset))
    logger().log('--------------------------------')

    # Print Variable Name
    logger().log(u'Name      : {}'.format(efi_var_name))
    # Print Variable GUID
    logger().log('Guid      : {}'.format(efi_var_guid))

    # Print Variable State
    if EFI_var_header:
        if 'State' in EFI_var_header._fields:
            state = getattr(EFI_var_header, 'State')
            state_str = 'State     :'
            if uefi_platform.IS_VARIABLE_STATE(state, uefi_platform.VAR_IN_DELETED_TRANSITION):
                state_str = state_str + ' IN_DELETED_TRANSITION +'
            if uefi_platform.IS_VARIABLE_STATE(state, uefi_platform.VAR_DELETED):
                state_str = state_str + ' DELETED +'
            if uefi_platform.IS_VARIABLE_STATE(state, uefi_platform.VAR_ADDED):
                state_str = state_str + ' ADDED +'
            logger().log(state_str)

        # Print Variable Complete Header
        if logger().VERBOSE:
            if EFI_var_header.__str__:
                logger().log(EFI_var_header)
            else:
                logger().log('Decoded Header ({}):'.format(uefi_platform.EFI_VAR_DICT[uefi_platform.FWType.EFI_FW_TYPE_UEFI]['name']))
                for attr in EFI_var_header._fields:
                    logger().log('{} = {:X}'.format('{0:<16}'.format(attr), getattr(EFI_var_header, attr)))

    attr_str = ('Attributes: 0x{:X} ( {} )'.format(efi_var_attributes, get_attr_string(efi_var_attributes)))
    logger().log(attr_str)

    # Print Variable Data
    logger().log('Data:')
    print_buffer(bytestostring(efi_var_data))

    # Print Variable Full Contents
    if logger().VERBOSE:
        logger().log('Full Contents:')
        if not efi_var_buf is None:
            print_buffer(bytestostring(efi_var_buf))


def print_sorted_EFI_variables(variables):
    sorted_names = sorted(variables.keys())
    for name in sorted_names:
        for rec in variables[name]:
            #                   off,    buf,     hdr,         data,   guid,   attrs
            print_efi_variable(rec[0], rec[1], rec[2], name, rec[3], rec[4], rec[5])


def decode_EFI_variables(efi_vars, nvram_pth):
    # print decoded and sorted EFI variables into a log file
    print_sorted_EFI_variables(efi_vars)
    # write each EFI variable into its own binary file
    for name in efi_vars.keys():
        n = 0
        for (off, buf, hdr, data, guid, attrs) in efi_vars[name]:
            # efi_vars[name] = (off, buf, hdr, data, guid, attrs)
            attr_str = get_attr_string(attrs)
            var_fname = os.path.join(nvram_pth, '{}_{}_{}_{:d}.bin'.format(name, guid, attr_str.strip(), n))
            write_file(var_fname, data)
            if name in SECURE_BOOT_KEY_VARIABLES:
                parse_efivar_file(var_fname, data, SECURE_BOOT_SIG_VAR)
            elif name == EFI_VAR_NAME_certdb:
                parse_efivar_file(var_fname, data, AUTH_SIG_VAR)
            elif name == EFI_VAR_NAME_AuthVarKeyDatabase:
                parse_efivar_file(var_fname, data, ESAL_SIG_VAR)
            n = n + 1


def identify_EFI_NVRAM(buffer):
    b = buffer
    for fw_type in uefi_platform.fw_types:
        # for t in uefi_platform.EFI_VAR_DICT.keys():
        if uefi_platform.EFI_VAR_DICT[fw_type]['func_getnvstore']:
            (offset, size, hdr) = uefi_platform.EFI_VAR_DICT[fw_type]['func_getnvstore'](b)
            if offset != -1:
                return fw_type

    return None


########################################################################################################
#
# UEFI HAL Component
#
########################################################################################################

class UEFI(hal_base.HALBase):
    def __init__(self, cs):
        super(UEFI, self).__init__(cs)
        self.helper = cs.helper
        # if cs is not None:
        #    self.cs = cs
        #    self.helper = cs.helper
        # else:
        #    self.helper = helper
        self._FWType = uefi_platform.FWType.EFI_FW_TYPE_UEFI

    ######################################################################
    # FWType defines platform/BIOS dependent formats like
    # format of EFI NVRAM, format of FV, etc.
    #
    # FWType chooses an element from the EFI_VAR_DICT Dictionary
    #
    # Default current platform type is EFI_FW_TYPE_UEFI
    ######################################################################

    def set_FWType(self, efi_nvram_format):
        if efi_nvram_format in uefi_platform.fw_types:
            self._FWType = efi_nvram_format

    ######################################################################
    # EFI NVRAM Parsing Functions
    ######################################################################

    def dump_EFI_variables_from_SPI(self):
        return self.read_EFI_variables_from_SPI(0, 0x800000)

    def read_EFI_variables_from_SPI(self, BIOS_region_base, BIOS_region_size):
        rom = self.cs.spi.read_spi(BIOS_region_base, BIOS_region_size)
        efi_var_store = self.find_EFI_variable_store(rom)
        if efi_var_store:
            efi_vars = uefi_platform.EFI_VAR_DICT[self._FWType]['func_getefivariables']
            return efi_vars
        return efi_var_store

    def read_EFI_variables_from_file(self, filename):
        rom = read_file(filename)
        efi_var_store = self.find_EFI_variable_store(rom)
        if efi_var_store:
            efi_vars = uefi_platform.EFI_VAR_DICT[self._FWType]['func_getefivariables']
            return efi_vars
        return efi_var_store

    def find_EFI_variable_store(self, rom_buffer):
        if (rom_buffer is None):
            logger().log_error('rom_buffer is None')
            return None

        rom = rom_buffer
        offset = 0
        size = len(rom_buffer)
        nvram_header = None

        if uefi_platform.EFI_VAR_DICT[self._FWType]['func_getnvstore']:
            (offset, size, nvram_header) = uefi_platform.EFI_VAR_DICT[self._FWType]['func_getnvstore'](rom)
            if (-1 == offset):
                logger().log_error("'func_getnvstore' is defined but could not find EFI NVRAM. Exiting..")
                return None
        else:
            logger().log("[uefi] 'func_getnvstore' is not defined in EFI_VAR_DICT. Assuming start offset 0..")

        if -1 == size:
            size = len(rom_buffer)
        nvram_buf = rom[offset: offset + size]

        if logger().UTIL_TRACE:
            logger().log('[uefi] Found EFI NVRAM at offset 0x{:08X}'.format(offset))
            logger().log("""
==================================================================
NVRAM: EFI Variable Store
==================================================================""")
            if nvram_header:
                logger().log(nvram_header)
        return nvram_buf

    # @TODO: Do not use, will be removed
    def read_EFI_variables(self, efi_var_store, authvars):
        if (efi_var_store is None):
            logger().log_error('efi_var_store is None')
            return None
        variables = uefi_platform.EFI_VAR_DICT[self._FWType]['func_getefivariables'](efi_var_store)
        if logger().UTIL_TRACE:
            print_sorted_EFI_variables(variables)
        return variables

    def parse_EFI_variables(self, fname, rom, authvars, _fw_type=None):
        if _fw_type in uefi_platform.fw_types:
            logger().log("[uefi] Using FW type (NVRAM format): {}".format(_fw_type))
            self.set_FWType(_fw_type)
        else:
            logger().log_error("Unrecognized FW type (NVRAM format) '{}'..".format(_fw_type))
            return False

        logger().log("[uefi] Searching for NVRAM in the binary..")
        efi_vars_store = self.find_EFI_variable_store(rom)
        if efi_vars_store:
            nvram_fname = fname + '.nvram.bin'
            write_file(nvram_fname, efi_vars_store)
            nvram_pth = fname + '.nvram.dir'
            if not os.path.exists(nvram_pth):
                os.makedirs(nvram_pth)
            logger().log("[uefi] Extracting EFI Variables in the NVRAM..")
            efi_vars = uefi_platform.EFI_VAR_DICT[self._FWType]['func_getefivariables'](efi_vars_store)
            decode_EFI_variables(efi_vars, nvram_pth)
        else:
            logger().log_error("Did not find NVRAM")
            return False

        return True

    def decompress_EFI_binary(self, compressed_name, uncompressed_name, compression_type):
        if logger().HAL:
            logger().log("[uefi] decompressing EFI binary (type = 0x{:X})\n       {} ->\n       {}".format(compression_type, compressed_name, uncompressed_name))
        if compression_type in COMPRESSION_TYPES:
            if self.cs.helper.decompress_file(compressed_name, uncompressed_name, compression_type):
                return read_file(uncompressed_name)
            else:
                return None
        else:
            logger().log_error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            return None

    def compress_EFI_binary(self, uncompressed_name, compressed_name, compression_type):
        if logger().HAL:
            logger().log("[uefi] compressing EFI binary (type = 0x{:X})\n       {} ->\n       {}".format(compression_type, uncompressed_name, compressed_name))
        if compression_type in COMPRESSION_TYPES:
            if self.cs.helper.compress_file(uncompressed_name, compressed_name, compression_type):
                return read_file(compressed_name)
            else:
                return None
        else:
            logger().log_error('Unknown EFI compression type 0x{:X}'.format(compression_type))
            return None

    ######################################################################
    # S3 Resume Boot-Script Parsing Functions
    ######################################################################

    #
    # Finds physical address of the S3 resume boot script from UEFI variables
    # Returns:
    #   found               - status is the script is found
    #   AcpiBootScriptTable - physical address of the S3 resume boot script, 0 if (not found)
    #
    def find_s3_bootscript(self):
        found = False
        BootScript_addresses = []

        efivars = self.list_EFI_variables()
        if efivars is None:
            logger().log_error('Could not enumerate UEFI variables at runtime')
            return (found, BootScript_addresses)
        if logger().HAL:
            logger().log("[uefi] searching for EFI variable(s): " + str(S3_BOOTSCRIPT_VARIABLES))

        for efivar_name in efivars:
            (off, buf, hdr, data, guid, attrs) = efivars[efivar_name][0]
            if efivar_name in S3_BOOTSCRIPT_VARIABLES:
                if logger().HAL:
                    logger().log("[uefi] found: {} {{{}}} {} variable".format(efivar_name, guid, get_attr_string(attrs)))
                if logger().HAL:
                    logger().log('[uefi] {} variable data:'.format(efivar_name))
                    print_buffer(bytestostring(data))

                varsz = len(data)
                if 4 == varsz:
                    AcpiGlobalAddr_fmt = '<L'
                elif 8 == varsz:
                    AcpiGlobalAddr_fmt = '<Q'
                else:
                    logger().log_error("Unrecognized format of '{}' UEFI variable (data size = 0x{:X})".format(efivar_name, varsz))
                    break
                AcpiGlobalAddr = struct.unpack_from(AcpiGlobalAddr_fmt, data)[0]
                if 0 == AcpiGlobalAddr:
                    logger().log_error("Pointer to ACPI Global Data structure in {} variable is 0".format(efivar_name))
                    break
                if logger().HAL:
                    logger().log("[uefi] Pointer to ACPI Global Data structure: 0x{:016X}".format(AcpiGlobalAddr))
                if logger().HAL:
                    logger().log("[uefi] Decoding ACPI Global Data structure..")
                AcpiVariableSet = self.helper.read_physical_mem(AcpiGlobalAddr, ACPI_VARIABLE_SET_STRUCT_SIZE)
                if logger().HAL:
                    logger().log('[uefi] AcpiVariableSet structure:')
                    print_buffer(bytestostring(AcpiVariableSet))
                AcpiVariableSet_fmt = '<6Q'
                # if len(AcpiVariableSet) < struct.calcsize(AcpiVariableSet_fmt):
                #    logger().log_error( 'Unrecognized format of AcpiVariableSet structure' )
                #    return (False,0)
                AcpiReservedMemoryBase, AcpiReservedMemorySize, S3ReservedLowMemoryBase, AcpiBootScriptTable, RuntimeScriptTableBase, AcpiFacsTable = struct.unpack_from(AcpiVariableSet_fmt, AcpiVariableSet)
                if logger().HAL:
                    logger().log('[uefi] ACPI Boot-Script table base = 0x{:016X}'.format(AcpiBootScriptTable))
                found = True
                BootScript_addresses.append(AcpiBootScriptTable)
                # break
        return (found, BootScript_addresses)

    #
    # Upper level function to find and parse S3 resume boot script
    # Returns:
    #   bootscript_pa  - physical address of the S3 resume boot script
    #   script_entries - a list of parse S3 resume boot script operations
    #
    def get_s3_bootscript(self, log_script=False):
        parsed_scripts = {}
        script_entries = []
        #
        # Find the S3 Resume Boot-Script from UEFI variables
        #
        found, bootscript_PAs = self.find_s3_bootscript()
        if not found:
            return (bootscript_PAs, None)
        if logger().HAL:
            logger().log('[uefi] Found {:d} S3 resume boot-scripts'.format(len(bootscript_PAs)))

        for bootscript_pa in bootscript_PAs:
            if (bootscript_pa == 0):
                continue
            if logger().HAL:
                logger().log('[uefi] S3 resume boot-script at 0x{:016X}'.format(bootscript_pa))
            #
            # Decode the S3 Resume Boot-Script into a sequence of operations/opcodes
            #
            # @TODO: should be dumping memory contents in a loop until end opcode is found or id'ing actual size
            script_buffer = self.helper.read_physical_mem(bootscript_pa, 0x200000)
            if logger().HAL:
                logger().log('[uefi] Decoding S3 Resume Boot-Script..')
            script_entries = parse_script(script_buffer, log_script)
            parsed_scripts[bootscript_pa] = script_entries
        return (bootscript_PAs, parsed_scripts)

    ######################################################################
    # Runtime Variable API Functions
    ######################################################################

    def list_EFI_variables(self):
        return self.helper.list_EFI_variables()

    def get_EFI_variable(self, name, guid, filename=None):
        var = self.helper.get_EFI_variable(name, guid)
        if var:
            if filename:
                write_file(filename, var)
            if logger().UTIL_TRACE or logger().HAL:
                logger().log('[uefi] EFI variable {}:{} :'.format(guid, name))
                print_buffer(bytestostring(var))
        return var

    def set_EFI_variable(self, name, guid, var, datasize=None, attrs=None):
        if logger().HAL:
            logger().log('[uefi] writing EFI variable {}:{} {}'.format(guid, name, '' if attrs is None else ('(attributes = {})'.format(attrs))))
            #print_buffer( var )
        return self.helper.set_EFI_variable(name, guid, var, datasize, attrs)

    def set_EFI_variable_from_file(self, name, guid, filename, datasize=None, attrs=None):
        if filename is None:
            logger().log_error('File with EFI variable is not specified')
            return False
        var = read_file(filename)
        return self.set_EFI_variable(name, guid, var, datasize, attrs)

    def delete_EFI_variable(self, name, guid):
        if logger().HAL:
            logger().log('[uefi] deleting EFI variable {}:{}'.format(guid, name))
        return self.helper.delete_EFI_variable(name, guid)

    ######################################################################
    # UEFI System Tables
    ######################################################################

    def find_EFI_Table(self, table_sig):
        (smram_base, _, _) = self.cs.cpu.get_SMRAM()
        CHUNK_SZ = 1024 * 1024  # 1MB
        if logger().HAL:
            logger().log("[uefi] Searching memory for EFI table with signature '{}' ..".format(table_sig))
        table_pa, table_header, table, table_buf = None, None, None, None
        pa = smram_base - CHUNK_SZ
        isFound = False

        (tseg_base, tseg_limit, _) = self.cs.cpu.get_TSEG()

        while pa > CHUNK_SZ:
            if (pa <= tseg_limit) and (pa >= tseg_base):
                if logger().HAL:
                    logger().log("[uefi] Skipping memory read at pa: {:016X}".format(pa))
                pa -= CHUNK_SZ
                continue
            if logger().HAL:
                logger().log('[uefi] Reading 0x{:016X}..'.format(pa))
            try:
                membuf = self.cs.mem.read_physical_mem(pa, CHUNK_SZ)
            except OsHelperError as err:
                if logger().HAL:
                    logger().log("[uefi] Unable to read memory at pa: {:016X} Error: {}".format(pa, err))
                pa -= CHUNK_SZ
                continue
            pos = bytestostring(membuf).find(table_sig)
            if -1 != pos:
                table_pa = pa + pos
                if logger().HAL:
                    logger().log("[uefi] Round signature '{}' at 0x{:016X}..".format(table_sig, table_pa))
                if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE):
                    hdr = membuf[pos: pos + EFI_TABLE_HEADER_SIZE]
                else:
                    hdr = self.cs.mem.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE)
                table_header = EFI_TABLE_HEADER(*struct.unpack_from(EFI_TABLE_HEADER_FMT, hdr))
                # do some sanity checks on the header
                is_reserved = table_header.Reserved != 0
                is_bad_crc = table_header.CRC32 == 0
                is_not_table_rev = table_header.Revision not in EFI_REVISIONS
                is_not_correct_size = table_header.HeaderSize > MAX_EFI_TABLE_SIZE
                if is_reserved or is_bad_crc or is_not_table_rev or is_not_correct_size:
                    if logger().HAL:
                        logger().log("[uefi] Found '{}' at 0x{:016X} but doesn't look like an actual table. Keep searching...".format(table_sig, table_pa))
                        logger().log(table_header)
                else:
                    isFound = True
                    if logger().HAL:
                        logger().log("[uefi] Found EFI table at 0x{:016X} with signature '{}'...".format(table_pa, table_sig))
                    table_size = struct.calcsize(EFI_TABLES[table_sig]['fmt'])
                    if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE - table_size):
                        table_buf = membuf[pos: pos + EFI_TABLE_HEADER_SIZE + table_size]
                    else:
                        table_buf = self.cs.mem.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE + table_size)
                    table = EFI_TABLES[table_sig]['struct'](*struct.unpack_from(EFI_TABLES[table_sig]['fmt'], table_buf[EFI_TABLE_HEADER_SIZE:]))
                    if logger().HAL:
                        print_buffer(bytestostring(table_buf))
                        logger().log('[uefi] {}:'.format(EFI_TABLES[table_sig]['name']))
                        logger().log(table_header)
                        logger().log(table)
                    break
            pa -= CHUNK_SZ
        if (not isFound) and logger().HAL:
            logger().log("[uefi] Could not find EFI table with signature '{}'".format(table_sig))
        return (isFound, table_pa, table_header, table, table_buf)

    def find_EFI_System_Table(self):
        return self.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

    def find_EFI_RuntimeServices_Table(self):
        return self.find_EFI_Table(EFI_RUNTIME_SERVICES_SIGNATURE)

    def find_EFI_BootServices_Table(self):
        return self.find_EFI_Table(EFI_BOOT_SERVICES_SIGNATURE)

    def find_EFI_DXEServices_Table(self):
        return self.find_EFI_Table(EFI_DXE_SERVICES_TABLE_SIGNATURE)
    # def find_EFI_PEI_Table( self ):
    #    return self.find_EFI_Table( EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE )
    # def find_EFI_SMM_System_Table( self ):
    #    return self.find_EFI_Table( EFI_SMM_SYSTEM_TABLE_SIGNATURE )

    def find_EFI_Configuration_Table(self):
        ect_pa = None
        ect = None
        ect_buf = None
        (isFound, est_pa, est_header, est, est_buf) = self.find_EFI_System_Table()
        if isFound and est is not None:
            if 0 != est.BootServices:
                if logger().HAL:
                    logger().log("[uefi] UEFI appears to be in Boot mode")
                ect_pa = est.ConfigurationTable
            else:
                if logger().HAL:
                    logger().log("[uefi] UEFI appears to be in Runtime mode")
                ect_pa = self.cs.mem.va2pa(est.ConfigurationTable)
                if not ect_pa:
                    # Most likely the VA in the System Table is not mapped so find the RST by signature and
                    # then compute the address of the configuration table.  This assumes the VA mapping keeps
                    # the pages in the same relative location as in physical memory.
                    (rst_found, rst_pa, rst_header, rst, rst_buf) = self.find_EFI_RuntimeServices_Table()
                    if rst_found:
                        if logger().HAL:
                            logger().log_warning("Attempting to derive configuration table address")
                        ect_pa = rst_pa + (est.ConfigurationTable - est.RuntimeServices)
                    else:
                        if logger().HAL:
                            logger().log_warning("Can't find UEFI ConfigurationTable")
                        return (None, ect_pa, ect, ect_buf)

        if logger().HAL:
            logger().log("[uefi] EFI Configuration Table ({:d} entries): VA = 0x{:016X}, PA = 0x{:016X}".format(est.NumberOfTableEntries, est.ConfigurationTable, ect_pa))

        found = (ect_pa is not None)
        if found:
            ect_buf = self.cs.mem.read_physical_mem(ect_pa, EFI_VENDOR_TABLE_SIZE * est.NumberOfTableEntries)
            ect = EFI_CONFIGURATION_TABLE()
            for i in range(est.NumberOfTableEntries):
                vt = EFI_VENDOR_TABLE(*struct.unpack_from(EFI_VENDOR_TABLE_FORMAT, ect_buf[i * EFI_VENDOR_TABLE_SIZE:]))
                ect.VendorTables[vt.VendorGuid()] = vt.VendorTable
        return (found, ect_pa, ect, ect_buf)

    def dump_EFI_tables(self):
        (found, pa, hdr, table, table_buf) = self.find_EFI_System_Table()
        if found:
            logger().log("[uefi] EFI System Table:")
            print_buffer(bytestostring(table_buf))
            logger().log(hdr)
            logger().log(table)
        (found, ect_pa, ect, ect_buf) = self.find_EFI_Configuration_Table()
        if found:
            logger().log("\n[uefi] EFI Configuration Table:")
            print_buffer(bytestostring(ect_buf))
            logger().log(ect)
        (found, pa, hdr, table, table_buf) = self.find_EFI_RuntimeServices_Table()
        if found:
            logger().log("\n[uefi] EFI Runtime Services Table:")
            print_buffer(bytestostring(table_buf))
            logger().log(hdr)
            logger().log(table)
        (found, pa, hdr, table, table_buf) = self.find_EFI_BootServices_Table()
        if found:
            logger().log("\n[uefi] EFI Boot Services Table:")
            print_buffer(bytestostring(table_buf))
            logger().log(hdr)
            logger().log(table)
        (found, pa, hdr, table, table_buf) = self.find_EFI_DXEServices_Table()
        if found:
            logger().log("\n[uefi] EFI DXE Services Table:")
            print_buffer(bytestostring(table_buf))
            logger().log(hdr)
            logger().log(table)
