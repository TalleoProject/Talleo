/*
Copyright (c) 2020, The Talleo developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef WIN32
#include <windows.h>
#else
#include <iostream>
#endif

inline void hidecursor() {
#ifdef WIN32
    HANDLE hdl = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursor;
    GetConsoleCursorInfo(hdl, &cursor);
    cursor.bVisible = false;
    SetConsoleCursorInfo(hdl, &cursor);
#else
    std::cout << "\033[?25l" << std::flush;
#endif
}

inline void showcursor() {
#ifdef WIN32
    HANDLE hdl = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursor;
    GetConsoleCursorInfo(hdl, &cursor);
    cursor.bVisible = true;
    SetConsoleCursorInfo(hdl, &cursor);
#else
    std::cout << "\033[?25h" << std::flush;
#endif
}
