/*
    ____________________________________________________________________
    ====================================================================
                  ,~,
         ._____. (###è
        /####### `###´                                    ______  ______
       é##é`¨¨´   é##\__   ___           ___  .-----. _  /###### /######
       ##é####è,  è#é###è. \##è         é##/ é##!¨!#èé#è ##é`¨¨´ ##é`¨¨´
       `#!#!#!##è é#é~´`##  `##\  .ô.  /##´ é###| |####! `!#è~~. `!#è~~.
      __   .~é##´ é##   ##   `##\é###è/##´  ####| |####! __  è## __  è##
     é#è~é####´  é##é  .##è   `####'####´   \###è~é####! é#è~### é#è~###
     `######´    `~#´  `###     `#´ `#´      `!####!´`#´ `#####´ `#####´
    =====================================================================
    =====================================================================
    shwass 		- 	Shoooow ya' assssss!
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
            Program for analyzing and disassembling Mach-O files
                                x86-64
 
    Copyright (C) 2014  vtdiaz
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include "shwass.h"

int main (int argc, char** argv)
{
    shell_obj_t shell;
    static int thread = 0;
    do {
        shell.interact (thread);
        thread += 1;
    } while (shell.get_status() != DONE);
    
    return 0;
}
