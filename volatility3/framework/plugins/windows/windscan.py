import logging
import os
from typing import Iterable, List, Optional, Tuple, Type

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import windowstations
from volatility3.plugins.windows import info, poolscanner, modscan

vollog = logging.getLogger(__name__)


class WindScan(interfaces.plugins.PluginInterface):
    """Scans for window station objects in a windows memory image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'poolscanner', component = poolscanner.PoolScanner, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
        ]

    @staticmethod
    def create_windscan_constraints(context: interfaces.context.ContextInterface, symbol_table: str) -> List[poolscanner.PoolConstraint]:
        """Creates a list of Pool Tag Constraints for window station objects.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the symbols / types

        Returns:
            The list containing the built constraints.
        """

        wind_size = context.symbol_space.get_type(symbol_table + constants.BANG + "tagWINDOWSTATION").size

        return [
            # Unprotected Window Station
            poolscanner.PoolConstraint(b'Wind',
                                       object_type = "tagWINDOWSTATION",
                                       type_name = symbol_table + constants.BANG + "tagWINDOWSTATION",
                                       size = (wind_size, None),
                                       page_type = poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
                                       skip_type_test = True),
            # Protected Window Station
            poolscanner.PoolConstraint(b'Win\xe4',
                                       object_type = "tagWINDOWSTATION",
                                       type_name = symbol_table + constants.BANG + "tagWINDOWSTATION",
                                       size = (wind_size, None),
                                       page_type = poolscanner.PoolType.NONPAGED | poolscanner.PoolType.FREE,
                                       skip_type_test = True),
        ]

    @classmethod
    def determine_windows_version(cls, context: interfaces.context.ContextInterface, layer_name: str, nt_symbol_table: str) -> Tuple[str, Type]:
        """Tries to determine which symbol filename to use. The logic is partially taken from the info plugin and the netscan plugin.

        Args:
            context: The context from which to retrieve required elements (layers, symbol tables)
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols

        Returns:
            The filename of the symbol table to use.
        """

        # Really, the layout of the tagWINDOWSTATION hasn't changed much in Windows.
        # So we can get away with the major vesion. However, to avoid being a hostage
        # to fortune, let's get the minor version too... just in case.

        is_64bit = symbols.symbol_table_is_64bit(context, nt_symbol_table)

        is_18363_or_later = versions.is_win10_18363_or_later(context = context, symbol_table = nt_symbol_table)

        if is_64bit:
            arch = "x64"
        else:
            arch = "x86"

        vers = info.Info.get_version_structure(context, layer_name, nt_symbol_table)

        kuser = info.Info.get_kuser_structure(context, layer_name, nt_symbol_table)

        try:
            vers_minor_version = int(vers.MinorVersion)
            nt_major_version = int(kuser.NtMajorVersion)
            nt_minor_version = int(kuser.NtMinorVersion)
        except ValueError:
            # vers struct exists, but is not an int anymore?
            raise NotImplementedError("Kernel Debug Structure version format not supported!")
        except:
            # unsure what to raise here? Shamelessly stolen from netscan.
            raise exceptions.VolatilityException("Kernel Debug Structure missing VERSION/KUSER structure, unable to determine Windows version!")

        vollog.debug("Determined OS Version: {}.{} {}.{}".format(kuser.NtMajorVersion, kuser.NtMinorVersion, vers.MajorVersion, vers.MinorVersion))

        # Even though the layout of tagWINDOWSTATION hasn't changed much, we list version
        # *and* architecture in case we need to do something special in the future
        if arch == "x86":
            version_dict = {
                (6, 0, 6000): "windscan-vista-x86",
                (6, 0, 6001): "windscan-vista-x86",
                (6, 0, 6002): "windscan-vista-x86",
                (6, 0, 6003): "windscan-vista-x86",
                (6, 1, 7600): "windscan-win7-x86",
                (6, 1, 7601): "windscan-win7-x86",
                (6, 1, 8400): "windscan-win7-x86",
                (6, 2, 9200): "windscan-win8-x86",
                (6, 3, 9600): "windscan-win8-x86",
                (10, 0, 10240): "windscan-win8-x86",
                (10, 0, 10586): "windscan-win8-x86",
                (10, 0, 14393): "windscan-win8-x86",
                (10, 0, 15063): "windscan-win8-x86",
                (10, 0, 16299): "windscan-win8-x86",
                (10, 0, 17134): "windscan-win8-x86",
                (10, 0, 17763): "windscan-win8-x86",
                (10, 0, 18362): "windscan-win8-x86",
                (10, 0, 18363): "windscan-win8-x86",
            }
        else:
            version_dict = {
                (6, 0, 6000): "windscan-vista-x64",
                (6, 0, 6001): "windscan-vista-x64",
                (6, 0, 6002): "windscan-vista-x64",
                (6, 0, 6003): "windscan-vista-x64",
                (6, 1, 7600): "windscan-win7-x64",
                (6, 1, 7601): "windscan-win7-x64",
                (6, 1, 8400): "windscan-win7-x64",
                (6, 2, 9200): "windscan-win8-x64",
                (6, 3, 9600): "windscan-win8-x64",
                (10, 0, 10240): "windscan-win8-x64",
                (10, 0, 10586): "windscan-win8-x64",
                (10, 0, 14393): "windscan-win8-x64",
                (10, 0, 15063): "windscan-win8-x64",
                (10, 0, 16299): "windscan-win8-x64",
                (10, 0, 17134): "windscan-win8-x64",
                (10, 0, 17763): "windscan-win8-x64",
                (10, 0, 18362): "windscan-win8-x64",
                (10, 0, 19041): "windscan-win8-x64",
            }

        # special use case: Win10_18363 is not recognized by windows.info as 18363
        # because all kernel file headers and debug structures report 18363 as
        # "10.0.18362.1198" with the last part being incremented. However, we can use
        # os_distinguisher to differentiate between 18362 and 18363
        if vers_minor_version == 18362 and is_18363_or_later:
            vollog.debug("Detected 18363 data structures: working with 18363 symbol table.")
            vers_minor_version = 18363

        # when determining the symbol file we have to consider the following cases:
        # the determined version's symbol file is found by intermed.create -> proceed
        # the determined version's symbol file is not found by intermed -> intermed will throw an exc and abort
        # the determined version has no mapped symbol file -> if win10 use latest, otherwise throw exc
        # windows version cannot be determined -> throw exc
        filename = version_dict.get((nt_major_version, nt_minor_version, vers_minor_version))
        if not filename:
            # no match on filename means that we possibly have a version newer than those listed here.
            # try to grab the latest supported version of the current image NT version. If that symbol
            # version does not work, support has to be added manually.
            current_versions = [
                key for key in list(version_dict.keys()) if key[0] == nt_major_version and key[1] == nt_minor_version
            ]
            current_versions.sort()

            if current_versions:
                latest_version = current_versions[-1]

                filename = version_dict.get(latest_version)
                vollog.debug(f"Unable to find exact matching symbol file, going with latest: {filename}")
            else:
                raise NotImplementedError("This version of Windows is not supported: {}.{} {}.{}!".format(nt_major_version, nt_minor_version, vers.MajorVersion, vers_minor_version))

        vollog.debug(f"Determined symbol filename: {filename}")

        return filename, windowstations.class_types

    @classmethod
    def create_windscan_symbol_table(cls, context: interfaces.context.ContextInterface, layer_name: str, nt_symbol_table: str, config_path: str) -> str:
        """Creates a symbol table for window station objects.

        Args:
            context: The context from which to retrieve required elements (layers, symbol tables)
            layer_name: The name of the layer on which to operate
            nt_symbol_table: The name of the table containing the kernel symbols
            config_path: The config path where to find symbol files

        Returns:
            The name of the constructed symbol table
        """
        table_mapping = {"nt_symbols": nt_symbol_table}

        symbol_filename, class_types = cls.determine_windows_version(context, layer_name, nt_symbol_table)

        return intermed.IntermediateSymbolTable.create(context,
                                                       config_path,
                                                       os.path.join("windows", "windscan"),
                                                       symbol_filename,
                                                       class_types = class_types,
                                                       table_mapping = table_mapping)

    @classmethod
    def scan(cls,
             context: interfaces.context.ContextInterface,
             layer_name: str,
             symbol_table: str,
             windscan_symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for window station objects using the poolscanner module and constraints.

        Args:
            context: The context from which to retrieve required elements (layers, symbol tables)
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            windscan_symbol_table: The name of the table containing the window station object symbols

        Returns:
            A list of window station objects found by scanning the `layer_name` layer for window station pool signatures
        """

        constraints = cls.create_windscan_constraints(context, windscan_symbol_table)

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        """ Generates the window station objects for use in rendering. """

        kernel = self.context.modules[self.config['kernel']]

        windscan_symbol_table = self.create_windscan_symbol_table(self.context, kernel.layer_name,
                                                                kernel.symbol_table_name,
                                                                self.config_path)

        # session_layers = list(modscan.ModScan.get_session_layers(self.context, kernel.layer_name, kernel.symbol_table_name))

        for wind_obj in self.scan(self.context, kernel.layer_name, kernel.symbol_table_name, windscan_symbol_table):
            
            if not wind_obj.is_valid():
                vollog.debug(f"Potential wind obj @ 0x{wind_obj.vol.offset:2x} failed validation.")
                continue

            vollog.debug(f"Found wind obj @ 0x{wind_obj.vol.offset:2x} of assumed type {type(wind_obj)}")

            if isinstance(wind_obj, windowstations.WindowStation):
                vollog.debug(f"Found tagWINDOWSTATION @ 0x{wind_obj.vol.offset:2x}")

                desktop_count = wind_obj.get_desktop_count()
                if desktop_count < 1:
                    vollog.debug("Invalid number of desktops. Skipping this window station.")
                    continue

                yield (0, [
                    format_hints.Hex(wind_obj.vol.offset),
                    wind_obj.dwSessionId,
                    wind_obj.get_name(),
                    desktop_count,
                    format_hints.Hex(wind_obj.rpwinstaNext),
                    format_hints.Hex(wind_obj.rpdeskList),
                    format_hints.Hex(wind_obj.pGlobalAtomTable)
                ])

            else:
                # this should never happen, so log it.
                vollog.debug(f"Found window station object unsure of its type: {wind_obj} of type {type(wind_obj)}")
    
    def run(self):
        return renderers.TreeGrid([
            ("Offset", format_hints.Hex),
            ("dwSessionId", int),
            ("Name", str),
            ("Desktops", int),
            ("rpwinstaNext", format_hints.Hex),
            ("rpdeskList", format_hints.Hex),
            ("pGlobalAtomTable", format_hints.Hex),
        ], self._generator())


class Windows(interfaces.plugins.PluginInterface):
    """Displays a list of windows (tagWND)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'poolscanner', component = poolscanner.PoolScanner, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
        ]

    def _generator(self):

        windowstation_scanner = WindScan(self.context, self.config_path)
        kernel = self.context.modules[self.config['kernel']]
        windscan_symbol_table = windowstation_scanner.create_windscan_symbol_table(self.context, kernel.layer_name,
                                                                kernel.symbol_table_name,
                                                                self.config_path)

        for wind_obj in windowstation_scanner.scan(self.context, kernel.layer_name, kernel.symbol_table_name, windscan_symbol_table):
            
            if not wind_obj.is_valid():
                vollog.debug(f"Potential wind obj @ 0x{wind_obj.vol.offset:2x} failed validation.")
                continue

            vollog.debug(f"Found wind obj @ 0x{wind_obj.vol.offset:2x} of assumed type {type(wind_obj)}")

            if isinstance(wind_obj, windowstations.WindowStation):
                vollog.debug(f"Found tagWINDOWSTATION @ 0x{wind_obj.vol.offset:2x}")

                desktop_count = wind_obj.get_desktop_count()
                if desktop_count < 1:
                    vollog.debug("Invalid number of desktops. Skipping this window station.")
                    continue

                # At this point, we probably have a valid tagWINDOWSTATION
                
                # TODO: Must be a better way than passing the symbol type here?!
                desktop_symbol_type = windscan_symbol_table + constants.BANG + "tagDESKTOP"
                for desktop in wind_obj.desktops(desktop_symbol_type):
                    print(desktop.DeskInfo)
                    for wnd in desktop.windows(desktop.DeskInfo.spwnd):
                        print(type(wnd))
                        print(wnd)

                yield (0, [
                    format_hints.Hex(wind_obj.vol.offset),
                    wind_obj.dwSessionId,
                    wind_obj.get_name(),
                    desktop_count,
                    format_hints.Hex(wind_obj.rpwinstaNext),
                    format_hints.Hex(wind_obj.rpdeskList),
                    format_hints.Hex(wind_obj.pGlobalAtomTable)
                ])

            else:
                # this should never happen, so log it.
                vollog.debug(f"Found window station object unsure of its type: {wind_obj} of type {type(wind_obj)}")

    def run(self):
        return renderers.TreeGrid([
            ("Offset", format_hints.Hex),
            ("dwSessionId", int),
            ("Name", str),
            ("Desktops", int),
            ("rpwinstaNext", format_hints.Hex),
            ("rpdeskList", format_hints.Hex),
            ("pGlobalAtomTable", format_hints.Hex),
        ], self._generator())
