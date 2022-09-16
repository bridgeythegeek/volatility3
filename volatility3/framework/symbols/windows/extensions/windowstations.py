from typing import Dict, Tuple #, List, Union
from volatility3.framework import constants, objects, interfaces
from volatility3.framework.symbols.windows.extensions import pool

import logging
vollog = logging.getLogger(__name__)

class WindowStation(objects.StructType, pool.ExecutiveObject):

    def __init__(self, context: interfaces.context.ContextInterface, type_name: str,
                 object_info: interfaces.objects.ObjectInformation, size: int,
                 members: Dict[str, Tuple[int, interfaces.objects.Template]]) -> None:

        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         size = size,
                         members = members)
    
    def is_valid(self) -> bool:

        try:

            if self.rpdeskList < 0xf00000000000:
                return False
            
            if (self.rpwinstaNext < 0xf00000000000) and (not self.rpwinstaNext == 0x0):
                return False

            if self.dwSessionId >= 0xFF:
                return False
        
        except Exception as ex:
            vollog.debug(f"Exception: {ex}")
            return False

        return True
    
    def get_name(self) -> str:
        """Get the object's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore
    
    def get_desktop_count(self) -> int:
        """Get the number of desktops belonging to this window station."""
        desktop_count = 0
        this_desktop = self.rpdeskList
        while True:

            if this_desktop.is_valid():
                desktop_count += 1
            else:
                break
            
            if this_desktop.rpdeskNext == 0:
                break
            this_desktop = this_desktop.rpdeskNext
            
            if desktop_count == 99: # In emergency, break glass
                break
        
        return desktop_count
    
    def desktops(self, desktop_symbol_type):
        this_desktop = self.rpdeskList
        while True:

            if this_desktop.is_valid():
                yield self._context.object(desktop_symbol_type, layer_name=self.vol.native_layer_name, offset=this_desktop)
            else:
                break
            
            if this_desktop.rpdeskNext == 0:
                break
            this_desktop = this_desktop.rpdeskNext



class Desktop(objects.StructType, pool.ExecutiveObject):

    def is_valid(self) -> bool:

        try:

            self.pDeskInfo.dereference()
            self.rpdeskNext.dereference()
            self.rpwinstaParent.dereference()

        except Exception as ex:
            vollog.debug(f"Exception: {ex}")
            return False

        return True
    
    def get_name(self) -> str:
        """Get the object's name from the object header."""
        header = self.get_object_header()
        return header.NameInfo.Name.String  # type: ignore
    
    @property
    def DeskInfo(self):
        return self.pDeskInfo.dereference()
    
    # This windows function lifted straight from
    # Volatility 2... edited slightly
    def windows(self, win, filter = lambda x: True, level = 0):
        """Traverses windows in their Z order, bottom to top.

        @param win: an HWND to start. Usually this is the desktop 
        window currently in focus. 

        @param filter: a callable (usually lambda) to use for filtering
        the results. See below for examples:

        # only print subclassed windows
        filter = lambda x : x.lpfnWndProc == x.pcls.lpfnWndProc

        # only print processes named csrss.exe
        filter = lambda x : str(x.head.pti.ppi.Process.ImageFileName).lower() \
                                == "csrss.exe" if x.head.pti.ppi else False

        # only print processes by pid
        filter = lambda x : x.head.pti.pEThread.Cid.UniqueThread == 0x1020

        # only print visible windows
        filter = lambda x : 'WS_VISIBLE' not in x.get_flags() 
        """
        seen = set()
        wins = []
        
        cur = win
        while cur.is_valid():
            if cur.vol.offset in seen:
                break
            seen.add(cur.vol.offset)
            wins.append(cur)
            cur = cur.spwndNext.dereference()
        
        while wins:
            cur = wins.pop()
            if not filter(cur):
                continue

            yield cur, level

            if cur.spwndChild.is_valid():
                for xwin, xlevel in self.windows(cur.spwndChild, filter = filter, level = level + 1):
                    if xwin.vol.offset in seen:
                        break
                    yield xwin, xlevel
                    seen.add(xwin.vol.offset)


class DesktopInfo(objects.StructType):

    def is_valid(self) -> bool:
        return True


class Window(objects.StructType):

    def is_valid(self) -> bool:
        return True


class_types = {
    'tagWINDOWSTATION': WindowStation,
    'tagDESKTOP': Desktop,
    'tagDESKTOPINFO': DesktopInfo,
    'tagWND': Window,
}
