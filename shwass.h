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

#ifndef _shwass_h
#define _shwass_h

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/vm_prot.h>
#include <cstdint>
#include <termios.h>
#include <unistd.h>

typedef enum {
    FAIL = -1,
    BITx64 = 0,
    BIT32 = 0,
    BITx86 = 1,
    BIT64 = 1,
    FAT = 2,
    MULTIPLE = 2,
    UNIVERSAL = 2
} bit_type_t;

enum {
    INT = 0,
    CHAR = 1,
    U8 = 2,
    U16 = 3,
    U32 = 4,
    U64 = 5,
    U128 = 6,
    LOAD_COMMAND = 7,
    MACH_HEADER = 8,
    MACH_HEADER_64 = 9,
    SEGMENT_COMMAND = 10,
    SEGMENT_COMMAND_64 = 11,
    SECTION = 12,
    SECTION_64 = 13,
    DYLIB_COMMAND = 14,
    SYMTAB_COMMAND = 15,
    DYSYMTAB_COMMAND = 16,
    VERSION_MIN_COMMAND = 17,
    DYLD_INFO_COMMAND = 18,
    NLIST_64 = 19,
    NLIST = 20,
    LINKEDIT_DATA_COMMAND = 21,
    DYLINKER_COMMAND = 22,
    UUID_COMMAND = 23,
    RPATH_COMMAND = 24,
    SOURCE_VERSION_COMMAND = 25,
    FVMLIB = 26,
    FVMLIB_COMMAND = 27,
    DYLIB = 28,
    SUB_FRAMEWORK_COMMAND = 29,
    SUB_CLIENT_COMMAND = 30,
    SUB_UMBRELLA_COMMAND = 31,
    SUB_LIBRARY_COMMAND = 32,
    PREBOUND_DYLIB_COMMAND = 33,
    ROUTINES_COMMAND = 34,
    ROUTINES_COMMAND_64 = 35,
    DYLIB_TABLE_OF_CONTENTS = 36,
    DYLIB_MODULE = 37,
    DYLIB_MODULE_64 = 38,
    DYLIB_REFERENCE = 39,
    TWOLEVEL_HINTS_COMMAND = 40,
    TWOLEVEL_HINT = 41,
    PREBIND_CKSUM_COMMAND = 42,
    ENCRYPTION_INFO_COMMAND = 43,
    ENCRYPTION_INFO_COMMAND_64 = 44,
    LINKER_OPTION_COMMAND = 45,
    SYMSEG_COMMAND = 46,
    IDENT_COMMAND = 47,
    FVMFILE_COMMAND = 48,
    ENTRY_POINT_COMMAND = 49,
    DATA_IN_CODE_ENTRY = 50,
    TLV_DESCRIPTOR = 51
} index_types_t;

/*,,~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~,,
 *||                           Mach-O File Obj                          ||
 *``~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~´´
 */
typedef struct {
    uint32_t cmd, cmdsize;
    void* assisting_data;
    void* assisting_extra_data;
    bool data, xdata;
} load_command_info_t;

struct mach_header_fat {
    struct fat_header head;
    struct fat_arch* archs;
    void* specified_archs_headers;
};

typedef union {
    struct mach_header bit32;
    struct mach_header_64 bit64;
    struct mach_header_fat fat;
} macho_header_t;

typedef struct {
    macho_header_t header;
    load_command_info_t* cmds;
} macho_layout_t;

typedef struct {
    int field_type;
    std::string name;
} field_t;

struct mach_load_command_printable {
    std::string name;
    int nfields;
    field_t* fields;
    std::vector <std::string> tags;
};

#define _SCMLC  18
class macho_file_obj_t {
private:

    std::ifstream file;
    bit_type_t type;
    macho_layout_t layout;
    uint32_t data_allocated_metadata;
    bool swp; //    in case data is swapped (little-endian) ie. fat headers
    struct mach_load_command_printable mlc [_SCMLC];
    
    void abort_obj_init (const std::string);
    bit_type_t id_file ();
    void set_type (bit_type_t);
    void get_mach_header ();
    int get_file_layout ();
    int get_mach_load_commands ();
    std::string parse_cpu_type (cpu_type_t);
    std::string parse_cpu_subtype (cpu_type_t, cpu_subtype_t);
    std::string parse_filetype (uint32_t);
    void init_mlc ();
    
public:
    bool yes;
    macho_file_obj_t ();
    macho_file_obj_t (const std::string);
    ~macho_file_obj_t ()
    {
        abort_obj_init ("noreason");
        for (int i = 0; i < _SCMLC; i++)
        {
            free (mlc[i].fields);
        }
    }
    template <typename Type>
    Type readudata (bool swap = false);
    template <typename data_type>
    void readudatabytes (data_type*, size_t);
    size_t get_file_size ();
    uint32_t get_ncmds ();
    uint32_t get_sizeof_cmds ();
    bit_type_t id_cputype (cpu_type_t);
    int load_file (const std::string);
    int unload_file ();
    size_t get_file_pos ();
    int set_file_pos (const int);
    void show_macho_header ();
    void show_fat_macho_headers ();
    void show_segments_commands (const std::string);
    const int match_mlc_index (const std::string);
    void show_mach_load_command (const int);
    bit_type_t get_type ();
    template <typename Type>
    void dump_data (size_t);
    template <typename Type>
    Type req_data ();
    void rewind ();
};

/* data allocated */
#define _ALLOC_META         data_allocated_metadata
#define _ALLOC_FATARCHS     0x1000000
#define _ALLOC_FATHEADS     0x100000
#define _ALLOC_LCMDS        0x10000
#define _ALLOC_LCMDS_DATA   0x1000
#define _ALLOC_MLC_FIELDS   0x100

macho_file_obj_t::macho_file_obj_t ()
{
    yes = false;
    _ALLOC_META = 0x0;
    swp = false;
    init_mlc ();
}
/*
case NLIST_64:
std::cout << precond << "struct nlist_64 {\n";
std::cout << precond << "\tn_strx:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_type:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_sect:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_desc:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_value:\t";
bin.dump_data <uint64_t> (1*sizeof (uint64_t));
std::cout << precond << "\n}\n";
break;
case NLIST:
std::cout << precond << "struct nlist {\n";
std::cout << precond << "\tn_strx:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_type:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_sect:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_desc:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tn_value:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n}\n";
break;



case DYLIB_TABLE_OF_CONTENTS:
std::cout << precond << "struct dylib_table_of_contents {\n";
std::cout << precond << "\tsymbol_index:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tmodule_index:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n}\n";
break;
case DYLIB_MODULE:
std::cout << precond << "struct dylib_module {\n";
std::cout << precond << "\tmodule_name:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiextdefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnextdefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tirefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnrefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tilocalsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnlocalsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiextrel:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnextrel:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiinit_iterm:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tninit_nterm:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tobjc_module_info_addr:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tobjc_module_info_size:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n}\n";
break;
case DYLIB_MODULE_64:
std::cout << precond << "struct dylib_module_64 {\n";
std::cout << precond << "\tmodule_name:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiextdefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnextdefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tirefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnrefsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tilocalsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnlocalsym:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiextrel:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tnextrel:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tiinit_iterm:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tninit_nterm:\t\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tobjc_module_info_size:\t";
bin.dump_data <uint32_t> (1*sizeof (uint32_t));
std::cout << precond << "\n\tobjc_module_info_addr:\t";
bin.dump_data <uint64_t> (1*sizeof (uint64_t));
std::cout << precond << "\n}\n";
break;
*/

void macho_file_obj_t::init_mlc ()
{
    /*static*/ int mlc_counter = 0;

    /*
        Dylib Command   ===========     # 0
     */
    mlc[mlc_counter].name = "Dylib";
    mlc[mlc_counter].tags.push_back ("dylib");
    mlc[mlc_counter].tags.push_back ("dynamic lib");
    mlc[mlc_counter].tags.push_back ("dynamic library");
    mlc[mlc_counter].nfields = 5;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Dylib:";  // this actually contains offset to name relative to begining of load command
                                                // when displaying it will display actual string name
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Timestamp:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Current Version:";
    mlc[mlc_counter].fields[4].field_type = U32;
    mlc[mlc_counter].fields[4].name = "Compatibility Version:";
    /*
        End of Dylib Command
     */
    mlc_counter += 1;
    /*
        Symtab Command  ===========     # 1
     */
    mlc[mlc_counter].name = "Symtab";
    mlc[mlc_counter].tags.push_back ("symtab");
    mlc[mlc_counter].tags.push_back ("symbol table");
    mlc[mlc_counter].nfields = 5;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Symbol's offset:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Number of symbols:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "String's offset:";
    mlc[mlc_counter].fields[4].field_type = U32;
    mlc[mlc_counter].fields[4].name = "String's size:";
    /*
        End of Symtab Command
     */
    mlc_counter += 1;
    /*
        Dysymtab Command    ===========     # 2
     */
    mlc[mlc_counter].name = "Dysymtab";
    mlc[mlc_counter].tags.push_back ("dysymtab");
    mlc[mlc_counter].tags.push_back ("dynamic symtab");
    mlc[mlc_counter].tags.push_back ("dynamic symbol table");
    mlc[mlc_counter].nfields = 19;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Index to local symbols:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Number of local symbols:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Index to externally defined symbols:";
    mlc[mlc_counter].fields[4].field_type = U32;
    mlc[mlc_counter].fields[4].name = "Number of externally defined symbols:";
    mlc[mlc_counter].fields[5].field_type = U32;
    mlc[mlc_counter].fields[5].name = "Index to undefined symbols:";
    mlc[mlc_counter].fields[6].field_type = U32;
    mlc[mlc_counter].fields[6].name = "Number of undefined symbols:";
    mlc[mlc_counter].fields[7].field_type = U32;
    mlc[mlc_counter].fields[7].name = "Table of contents' offset:";
    mlc[mlc_counter].fields[8].field_type = U32;
    mlc[mlc_counter].fields[8].name = "Table of contents' entries:";
    mlc[mlc_counter].fields[9].field_type = U32;
    mlc[mlc_counter].fields[9].name = "Module table's offset:";
    mlc[mlc_counter].fields[10].field_type = U32;
    mlc[mlc_counter].fields[10].name = "Module table's entries:";
    mlc[mlc_counter].fields[11].field_type = U32;
    mlc[mlc_counter].fields[11].name = "Referenced symbol table's offset:";
    mlc[mlc_counter].fields[12].field_type = U32;
    mlc[mlc_counter].fields[12].name = "Referenced symbol table's entries:";
    mlc[mlc_counter].fields[13].field_type = U32;
    mlc[mlc_counter].fields[13].name = "Indirect symbol table's offset:";
    mlc[mlc_counter].fields[14].field_type = U32;
    mlc[mlc_counter].fields[14].name = "Indirect symbol table's entries:";
    mlc[mlc_counter].fields[15].field_type = U32;
    mlc[mlc_counter].fields[15].name = "External relocation entries' offset:";
    mlc[mlc_counter].fields[16].field_type = U32;
    mlc[mlc_counter].fields[16].name = "External relocation entries' entires:";
    mlc[mlc_counter].fields[17].field_type = U32;
    mlc[mlc_counter].fields[17].name = "Local relocation entries' offset:";
    mlc[mlc_counter].fields[18].field_type = U32;
    mlc[mlc_counter].fields[18].name = "Local relocation entries' entries:";
    /*
        End of Dysymtab Command
     */
    mlc_counter += 1;
    /*
        Version Min Command ===========     # 3
     */
    mlc[mlc_counter].name = "Version Min";
    mlc[mlc_counter].tags.push_back ("version min");
    mlc[mlc_counter].tags.push_back ("vermin");
    mlc[mlc_counter].nfields = 3;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Version:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "SDK:";
    /*
        End of Version Min Command
     */
    mlc_counter += 1;
    /*
        DYLD Info Command   ===========     # 4
     */
    mlc[mlc_counter].name = "DYLD Info";
    mlc[mlc_counter].tags.push_back ("dyld info");
    mlc[mlc_counter].tags.push_back ("dyld");
    mlc[mlc_counter].nfields = 11;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Rebase info offset:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Rebase info size:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Binding info offset:";
    mlc[mlc_counter].fields[4].field_type = U32;
    mlc[mlc_counter].fields[4].name = "Binding info size:";
    mlc[mlc_counter].fields[5].field_type = U32;
    mlc[mlc_counter].fields[5].name = "Weak binding info offset:";
    mlc[mlc_counter].fields[6].field_type = U32;
    mlc[mlc_counter].fields[6].name = "Weak binding info size:";
    mlc[mlc_counter].fields[7].field_type = U32;
    mlc[mlc_counter].fields[7].name = "Lazy binding info offset:";
    mlc[mlc_counter].fields[8].field_type = U32;
    mlc[mlc_counter].fields[8].name = "Lazy binding info size:";
    mlc[mlc_counter].fields[9].field_type = U32;
    mlc[mlc_counter].fields[9].name = "Exported symbol info:";
    mlc[mlc_counter].fields[10].field_type = U32;
    mlc[mlc_counter].fields[10].name = "Exported symbol size:";
    /*
        End of DYLD Info Command
     */
    mlc_counter += 1;
    /*
        Linkedit Data   ===========     # 5
     */
    mlc[mlc_counter].name = "Linkedit Data";
    mlc[mlc_counter].tags.push_back ("linkedit");
    mlc[mlc_counter].tags.push_back ("linkedit data");
    mlc[mlc_counter].nfields = 3;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Data offset:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Data size:";
    /*
        End of Linkedit Data
     */
    mlc_counter += 1;
    /*
        Dylinker Command    ===========     # 6
     */
    mlc[mlc_counter].name = "Dylinker";
    mlc[mlc_counter].tags.push_back ("dylinker");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Dylinker:";  // this actually contains offset to string name (relative to begining of load command)
                                                // when displaying it will display actual string name
    /*
        End of Dylinker Command
     */
    mlc_counter += 1;
    /*
        UUID Command        ===========     # 7
     */
    mlc[mlc_counter].name = "UUID";
    mlc[mlc_counter].tags.push_back ("uuid");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U128;
    mlc[mlc_counter].fields[1].name = "UUID:";
    /*
        End of UUID Command
     */
    mlc_counter += 1;
    /*
        Rpath Command       ===========     # 8
     */
    mlc[mlc_counter].name = "Rpath";
    mlc[mlc_counter].tags.push_back ("rpath");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Path:";  // this actually contains offset to string name (relative to begining of load command)
                                                // when displaying it will display actual string name
    /*
        End of Rpath Command
     */
    mlc_counter += 1;
    /*
        Source Version Command  ===========     # 9
     */
    mlc[mlc_counter].name = "Source Version";
    mlc[mlc_counter].tags.push_back ("source version");
    mlc[mlc_counter].tags.push_back ("source ver");
    mlc[mlc_counter].tags.push_back ("src version");
    mlc[mlc_counter].tags.push_back ("src ver");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Version:";
    /*
        End of Source Version Command
     */
    mlc_counter += 1;
    /*
        FVMLib Command      ===========     # 10
     */
    mlc[mlc_counter].name = "FVM Lib";
    mlc[mlc_counter].tags.push_back ("fvmlib");
    mlc[mlc_counter].tags.push_back ("fvm lib");
    mlc[mlc_counter].tags.push_back ("fvm library");
    mlc[mlc_counter].nfields = 4;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "FVM Lib:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Minor version:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Header Adress:";
    /*
        End of FVMLib Command
     */
    mlc_counter += 1;
    /*
        Sub Framework Command   ===========     # 11
     */
    mlc[mlc_counter].name = "Sub Framework";
    mlc[mlc_counter].tags.push_back ("subframework");
    mlc[mlc_counter].tags.push_back ("sub framework");
    mlc[mlc_counter].tags.push_back ("umbrella");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Umbrella:";  // this actually contains offset to string name (relative to begining of load command)
                                                    // when displaying it will display actual string name
    /*
        End of Sub Framework Command
     */
    mlc_counter += 1;
    /*
        Sub Client Command  ===========     # 12
     */
    mlc[mlc_counter].name = "Sub Client";
    mlc[mlc_counter].tags.push_back ("subclient");
    mlc[mlc_counter].tags.push_back ("sub client");
    mlc[mlc_counter].tags.push_back ("client");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Client:";    // this actually contains offset to string name (relative to begining of load command)
                                                    // when displaying it will display actual string name
    /*
        End of Sub Client Command
     */
    mlc_counter += 1;
    /*
        Sub Umbrella Command    ===========     # 13
     */
    mlc[mlc_counter].name = "Sub Umbrella";
    mlc[mlc_counter].tags.push_back ("subumbrella");
    mlc[mlc_counter].tags.push_back ("sub umbrella");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Sub Umbrella:";  // this actually contains offset to string name (relative to begining of load command)
                                                        // when displaying it will display actual string name
    /*
        End of Sub Umbrella Command
     */
    mlc_counter += 1;
    /*
        Sub Library Command     ===========     # 14
     */
    mlc[mlc_counter].name = "Sub Library";
    mlc[mlc_counter].tags.push_back ("sublib");
    mlc[mlc_counter].tags.push_back ("sub lib");
    mlc[mlc_counter].tags.push_back ("sublibrary");
    mlc[mlc_counter].tags.push_back ("sub library");
    mlc[mlc_counter].nfields = 2;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Sub Library:";   // this actually contains offset to string name (relative to begining of load command)
                                                        // when displaying it will display actual string name
    /*
        End of Sub Library Command
     */
    mlc_counter += 1;
    /*
        Pre-Bound Dylib Command ===========     # 15
     */
    mlc[mlc_counter].name = "Pre-bound Dylib";
    mlc[mlc_counter].tags.push_back ("pre dylib");
    mlc[mlc_counter].tags.push_back ("prebound dylib");
    mlc[mlc_counter].tags.push_back ("pre-bound dylib");
    mlc[mlc_counter].nfields = 4;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Pre-bound Dylib:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Modules:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Linked Modules:";
    /*
        End of Pre-Bound Dylib Command
     */
    mlc_counter += 1;
    /*
        Routines Command    ===========     # 16
     */
    mlc[mlc_counter].name = "Routines";
    mlc[mlc_counter].tags.push_back ("routines");
    mlc[mlc_counter].nfields = 9;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U32;
    mlc[mlc_counter].fields[1].name = "Initial address:";
    mlc[mlc_counter].fields[2].field_type = U32;
    mlc[mlc_counter].fields[2].name = "Initial module:";
    mlc[mlc_counter].fields[3].field_type = U32;
    mlc[mlc_counter].fields[3].name = "Reserved [1]:";
    mlc[mlc_counter].fields[4].field_type = U32;
    mlc[mlc_counter].fields[4].name = "Reserved [2]:";
    mlc[mlc_counter].fields[5].field_type = U32;
    mlc[mlc_counter].fields[5].name = "Reserved [3]:";
    mlc[mlc_counter].fields[6].field_type = U32;
    mlc[mlc_counter].fields[6].name = "Reserved [4]:";
    mlc[mlc_counter].fields[7].field_type = U32;
    mlc[mlc_counter].fields[7].name = "Reserved [5]:";
    mlc[mlc_counter].fields[8].field_type = U32;
    mlc[mlc_counter].fields[8].name = "Reserved [6]:";
    /*
        End of Routines Command
     */
    mlc_counter += 1;
    /*
        Routines Command 64-bit ===========     # 17
     */
    mlc[mlc_counter].name = "Routines";
    mlc[mlc_counter].tags.push_back ("routines-64");
    mlc[mlc_counter].tags.push_back ("routines 64");
        mlc[mlc_counter].tags.push_back ("routines 64-bit");
    mlc[mlc_counter].nfields = 9;
    mlc[mlc_counter].fields = (field_t*) malloc (sizeof (field_t) * mlc[mlc_counter].nfields);
    if (mlc[mlc_counter].fields == NULL)
        abort_obj_init ("there was a memory problem, could not initiate mach-o load commands printable info!");
    mlc[mlc_counter].fields[0].field_type = U32;
    mlc[mlc_counter].fields[0].name = "Size:";
    mlc[mlc_counter].fields[1].field_type = U64;
    mlc[mlc_counter].fields[1].name = "Initial address:";
    mlc[mlc_counter].fields[2].field_type = U64;
    mlc[mlc_counter].fields[2].name = "Initial module:";
    mlc[mlc_counter].fields[3].field_type = U64;
    mlc[mlc_counter].fields[3].name = "Reserved [1]:";
    mlc[mlc_counter].fields[4].field_type = U64;
    mlc[mlc_counter].fields[4].name = "Reserved [2]:";
    mlc[mlc_counter].fields[5].field_type = U64;
    mlc[mlc_counter].fields[5].name = "Reserved [3]:";
    mlc[mlc_counter].fields[6].field_type = U64;
    mlc[mlc_counter].fields[6].name = "Reserved [4]:";
    mlc[mlc_counter].fields[7].field_type = U64;
    mlc[mlc_counter].fields[7].name = "Reserved [5]:";
    mlc[mlc_counter].fields[8].field_type = U64;
    mlc[mlc_counter].fields[8].name = "Reserved [6]:";
    /*
        End of Routines Command 64-bit
     */
    data_allocated_metadata |= _ALLOC_MLC_FIELDS;
}

bit_type_t macho_file_obj_t::get_type ()
{
    return type;
}

int macho_file_obj_t::load_file (const std::string filename)
{
    if (file.is_open())
    {
        std::cout << "\033[5;31mfile already loaded!\n\033[0m";
        return -1;
    }
    file.open (filename, std::ifstream::binary | std::ifstream::in);
    if (!file.is_open())
    {
        std::cout << "\033[5;31mcould not open file!\n\033[0m";
        return -1;
    }
    const bit_type_t file_type = id_file ();
    if (file_type == FAIL)
    {
        abort_obj_init ("could not id file");
        return -1;
    }
    set_type (file_type);
    //const size_t filesize = get_file_size ();
    if (get_file_layout () < 0)
    {
        abort_obj_init ("could not get layout of binaries.");
        return -1;
    }
    yes = true;
    file.seekg (0, file.beg);
    return 0;
}

int macho_file_obj_t::unload_file ()
{
    if (file.is_open() == false)
    {
        std::cout << "\033[5;31mno file has been loaded!\n\033[0m";
        return -1;
    }
    abort_obj_init ("noreason");
    return 0;
}

macho_file_obj_t::macho_file_obj_t (const std::string filename)
{
    yes = false;
    file.open (filename, std::ifstream::binary | std::ifstream::in);
    if (!file.is_open())
    {
        std::cout << "\033[5;31mcould not open file!\n";
        return;
    }
    _ALLOC_META = 0x0;
    swp = false;
    const bit_type_t file_type = id_file ();
    if (file_type == FAIL)
    {
        abort_obj_init ("could not id file.");
        return;
    }
    set_type (file_type);
    //const size_t filesize = get_file_size ();
    if (get_file_layout () < 0)
    {
        abort_obj_init ("could not get layout of binaries.");
        return;
    }
    yes = true;
    file.seekg (0, file.beg);
    init_mlc ();
}

void macho_file_obj_t::abort_obj_init (const std::string reason)
{
    if (reason != "noreason")
    {
        std::cerr << "\033[1;31merr:\033[0m \033[5;31m" << reason << "\033[0m" << std::endl;
        std::cout << "aborting.........";
    }

    /*
        clean all mem allocation
     */
    if ((_ALLOC_META & _ALLOC_LCMDS_DATA) == _ALLOC_LCMDS_DATA)
    {
        const uint32_t cmds = get_ncmds ();
        if ((int) cmds <= 0)
        {
            //?
            exit (-1);
        }
        for (int i = 0; i < (int)cmds; i++)
        {
            if (layout.cmds[i].data == false && layout.cmds[i].xdata == false)
            {
                //?
                std::cout << "\033[0;31m?\n\033[0m";
            }
            if (layout.cmds[i].assisting_data == NULL && layout.cmds[i].assisting_extra_data == NULL)
            {
                //?
                std::cout << "\033[0;31m?\n\033[0m";
                continue;
            }
            
            if (layout.cmds[i].data)
            {
                if (layout.cmds[i].assisting_data)
                    free (layout.cmds[i].assisting_data);
            }
            if (layout.cmds[i].xdata)
            {
                if (layout.cmds[i].assisting_extra_data)
                    free (layout.cmds[i].assisting_extra_data);
            }
        }
    }
    if ((_ALLOC_META & _ALLOC_FATARCHS) == _ALLOC_FATARCHS)
    {
        if (layout.header.fat.archs == NULL)
        {
            std::cout << "\033[0;31m.?\n\033[0m";
            exit (-1);
        }
        free (layout.header.fat.archs);
    }
    if ((_ALLOC_META & _ALLOC_FATHEADS) == _ALLOC_FATHEADS)
    {
        if (layout.header.fat.specified_archs_headers == NULL)
        {
            std::cout << "\033[0;31m..?\n\033[0m";
            exit (-1);
        }
        free (layout.header.fat.specified_archs_headers);
    }
    if ((_ALLOC_META & _ALLOC_LCMDS) == _ALLOC_LCMDS)
    {
        if (layout.cmds == NULL)
        {
            std::cout << "\033[0;31m...?\n\033[0m";
            exit (-1);
        }
        free (layout.cmds);
    }
    if ((_ALLOC_META & _ALLOC_MLC_FIELDS) == _ALLOC_MLC_FIELDS)
    {
        /*for (int i = 0; i < _SCMLC; i++)
        {
            free (mlc[i].fields);
        }*/
    }
    if (file.is_open())
    {
        file.close ();
    }

    _ALLOC_META = 0x0;
    yes = false;
    swp = false;
    set_type (FAIL);
    
    std::cout << "\033[0;32m[OK]\033[0m" << std::endl;
    return;
}

bit_type_t macho_file_obj_t::id_file ()
{
    file.seekg (0, file.beg);
    switch (readudata <uint32_t> ())
    {
        case 0xcefaedfe:
            swp = true;
        case 0xfeedface:
            return BIT32;
            break;
        case 0xcffaedfe:
            swp = true;
        case 0xfeedfacf:
            return BIT64;
            break;
        case 0xbebafeca:
            swp = true;
        case 0xcafebabe:
            return FAT;
            break;
    }
    return FAIL;
}

void macho_file_obj_t::set_type (bit_type_t file_type)
{
    type = file_type;
}

bit_type_t macho_file_obj_t::id_cputype (cpu_type_t cpu)
{
    if (cpu == CPU_TYPE_X86)
        return BIT32;
    else if (cpu == CPU_TYPE_I386)
        return BIT32;
    else if (cpu == CPU_TYPE_X86_64)
        return BIT64;
    
    return FAIL;
}

size_t macho_file_obj_t::get_file_pos ()
{
    return file.tellg ();
}

int macho_file_obj_t::set_file_pos (const int pos)
{
    const size_t current_position = get_file_pos ();
    const size_t file_size = get_file_size ();
    if (pos + current_position < file_size && pos > 0)
    {
        file.seekg (0, file.beg);
        file.seekg (pos, file.cur);
        return 1;
    }
    else
    {
        return -1;
    }
    
    return 0;
}

void macho_file_obj_t::get_mach_header ()
{
    file.seekg (0, file.beg);
    
    if (type == BIT32)
    {
        if (swp)
        {
            abort_obj_init ("32-bit swapped binaries not implemented yet");
            return;
        }
        readudatabytes <uint8_t> ((uint8_t*) &layout.header.bit32, sizeof (struct mach_header));
    }
    else if (type == BIT64)
    {
        if (swp)
        {
            abort_obj_init ("64-bit swapped binaries not implemented yet");
            return;
        }
        readudatabytes <uint8_t> ((uint8_t*) &layout.header.bit64, sizeof (struct mach_header_64));
    }
    else if (type == FAT)
    {
        layout.header.fat.head.magic                    = readudata <uint32_t> (swp);
        const uint32_t narchs                           = readudata <uint32_t> (swp);

        if (narchs > 0x2) // only 32-bit & 64-bit supported
        {
            abort_obj_init ("more architectures in binaries than known");
            return;
        }
        else if ((int)narchs <= 0)
        {
            abort_obj_init ("bad nfat_arch value");
            return;
        }
        
        layout.header.fat.head.nfat_arch = narchs;
        layout.header.fat.archs = (struct fat_arch*) malloc (sizeof (struct fat_arch) * narchs);
        if (layout.header.fat.archs == NULL)
        {
            abort_obj_init ("could not allocate memory for fat_arch structures");
            return;
        }
        memset (layout.header.fat.archs, 0, sizeof (struct fat_arch) * narchs);
        _ALLOC_META |= _ALLOC_FATARCHS;
        for (int i = 0; i < (int)narchs; i++)
        {
            layout.header.fat.archs[i].cputype          = readudata <uint32_t> (swp);
            layout.header.fat.archs[i].cpusubtype       = readudata <uint32_t> (swp);
            layout.header.fat.archs[i].offset           = readudata <uint32_t> (swp);
            layout.header.fat.archs[i].size             = readudata <uint32_t> (swp);
            layout.header.fat.archs[i].align            = readudata <uint32_t> (swp);
        }
        
        size_t headers_size = 0;
        uint32_t offsets [(int)narchs];
        for (int i = 0; i < (int)narchs; i++)
        {
            offsets [i] = layout.header.fat.archs[i].offset;
            bit_type_t header_type = id_cputype (layout.header.fat.archs[i].cputype);
            if (header_type == BIT32)
            {
                headers_size += sizeof (struct mach_header);
            }
            else if (header_type == BIT64)
            {
                headers_size += sizeof (struct mach_header_64);
            }
            else if (header_type == FAIL)
            {
                abort_obj_init ("failed to recognize Mach-O header cpu type");
                return;
            }
            else
            {
                abort_obj_init ("unkown error: while identifying header cpu type");
                return;
            }
        }
        
        if (headers_size != (sizeof (struct mach_header) + sizeof (struct mach_header_64)))
        {
            abort_obj_init ("headers sizes don't match those of a 32-bit & 64-bit fat binary");
            return;
        }
        
        layout.header.fat.specified_archs_headers = (void*) malloc (headers_size);
        if (layout.header.fat.specified_archs_headers == NULL)
        {
            abort_obj_init ("could not allocate memory for fat archs header structures");
            return;
        }
        memset (layout.header.fat.specified_archs_headers, 0, headers_size);
        _ALLOC_META |= _ALLOC_FATHEADS;

        size_t buffer_spent = 0x0;
        for (int i = 0; i < (int)narchs; i++)
        {
            bit_type_t header_type = id_cputype (layout.header.fat.archs[i].cputype);
            if (header_type == BIT32)
            {
                file.seekg (0, file.beg);
                file.seekg (offsets[i], file.cur);
                if (buffer_spent >= headers_size || headers_size - buffer_spent < sizeof (struct mach_header))
                {
                    abort_obj_init ("not enough space in headers' buffer!");
                    return;
                }
                readudatabytes <uint8_t>
                ((uint8_t*) layout.header.fat.specified_archs_headers + buffer_spent, sizeof (struct mach_header));
                buffer_spent += sizeof (struct mach_header);
            }
            else if (header_type == BIT64)
            {
                file.seekg (0, file.beg);
                file.seekg (offsets[i], file.cur);
                if (buffer_spent >= headers_size || headers_size - buffer_spent < sizeof (struct mach_header_64))
                {
                    abort_obj_init ("not enough space in headers' buffer!");
                    return;
                }
                readudatabytes <uint8_t>
                ((uint8_t*) layout.header.fat.specified_archs_headers + buffer_spent, sizeof (struct mach_header_64));
                buffer_spent += sizeof (struct mach_header_64);
            }
            else
            {
                abort_obj_init ("unknown error: while getting architecture specific headers");
                return;
            }
        }
    }
}

void macho_file_obj_t::show_macho_header ()
{
    if (type == BIT32 || type == BIT64)
    {
        uint32_t* data32;
        if (type == BIT64)
        {
            data32 = (uint32_t*) &layout.header.bit64;
        }
        else
        {
            data32 = (uint32_t*) &layout.header.bit32;
        }
        std::cout << "\033[0;33m\t[ Header ======\n\033[0;35m\t\tMagic number:\033[0m\t\t0x" << std::hex << *data32 <<
        std::endl;
        data32++;
        const cpu_type_t cpu = *data32;
        std::cout << "\033[0;35m\t\tCPU Type:\033[0m\t\t" << parse_cpu_type (cpu) << " (0x" << std::hex << *data32 << ")" << std::endl;
        data32++;
        const cpu_subtype_t cpu_s = *data32;
        std::cout << "\033[0;35m\t\tCPU Subtype:\033[0m\t\t" << parse_cpu_subtype (cpu, cpu_s) << " (0x" << std::hex << *data32 << ")" << std::endl;
        data32++;
        std::cout << "\033[0;35m\t\tFiletype:\033[0m\t\t" << parse_filetype (*data32) << " (0x" << std::hex << *data32 << ")" << std::endl;
        data32++;
        std::cout << "\033[0;35m\t\tCmds count:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
        data32++;
        std::cout << "\033[0;35m\t\tSizeof cmds:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
        data32++;
        std::cout << "\033[0;35m\t\tFlags:\033[0m\t\t\t0x" << std::hex << *data32 << std::endl;
        if (type == BIT64)
        {
            data32++;
            std::cout << "\033[0;35m\t\tReserved:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
        }
        return;
    }
    else if (type == FAT)
    {
        std::cout << "\033[0;31mThis is a fat binary, if you'd like to see the headers of each arch try `show headers` instead\n\033[0m";
        std::cout << "\033[0;33m\t[ Header ======\n\033[0;35m\t\tMagic number:\033[0m\t0x" << std::hex << layout.header.fat.head.magic <<
                            std::endl;
        std::cout << "\033[0;35m\t\tArchs:\033[0m\t\t0x" << std::hex << layout.header.fat.head.nfat_arch << std::endl;
        for (int i = 0; i < (int)layout.header.fat.head.nfat_arch; i++)
        {
            std::cout << "\033[0;34m\t\t[Arch #\033[0m" << i << "\033[0;34m =====\n";
            std::cout <<    "\033[0;35m\t\t\tCPU type:\033[0m\t" << parse_cpu_type (layout.header.fat.archs[i].cputype) <<
                            " (0x" << std::hex << layout.header.fat.archs[i].cputype;
            std::cout <<    ")\n\033[0;35m\t\t\tCPU sub type:\033[0m\t" <<
                            parse_cpu_subtype (layout.header.fat.archs[i].cputype, layout.header.fat.archs[i].cpusubtype) <<
                            " (0x" << std::hex << layout.header.fat.archs[i].cpusubtype << ")" << std::endl;
            std::cout << "\033[0;35m\t\t\tOffset:\t\t\033[0m0x" << std::hex << layout.header.fat.archs[i].offset << std::endl;
            std::cout << "\033[0;35m\t\t\tSize:\t\t\033[0m0x" << std::hex << layout.header.fat.archs[i].size << std::endl;
            std::cout << "\033[0;35m\t\t\tAlign:\033[0m\t\t2^" << layout.header.fat.archs[i].align << std::endl;
        }
        
        return;
    }
    else
    {
        abort_obj_init ("file type should be known by now, lost it in macho_file_obj_t::show_macho_header()");
        return;
    }
}

void macho_file_obj_t::show_fat_macho_headers ()
{
    if (type != FAT)
    {
        abort_obj_init ("program reached macho_file_obj_t::show_fat_macho_headers () which should'nt be because file is not fat binary!");
        return;
    }
    
    size_t buffer_pos = 0x0;
    std::string type_str = "Undetermined";
    for (int i = 0; i < (int)layout.header.fat.head.nfat_arch; i++)
    {
        const bit_type_t header_type = id_cputype (layout.header.fat.archs[i].cputype);
        if (header_type == BIT32)
        {
            type_str = "32-bit";
        }
        else if (header_type == BIT64)
        {
            type_str = "64-bit";
        }
        if (header_type == BIT32 || header_type == BIT64)
        {
            uint32_t* data32;
            data32 = (uint32_t*)((uint8_t*)layout.header.fat.specified_archs_headers + buffer_pos);
            std::cout << "\033[0;33m\t[ Header " << type_str << " ======\n\033[0;35m\t\tMagic number:\033[0m\t\t0x" << std::hex << *data32 <<
            std::endl;
            data32++;
            const cpu_type_t cpu = *data32;
            std::cout << "\033[0;35m\t\tCPU Type:\033[0m\t\t" << parse_cpu_type (cpu) << " (0x" << std::hex << *data32 << ")" << std::endl;
            data32++;
            const cpu_subtype_t cpu_s = *data32;
            std::cout << "\033[0;35m\t\tCPU Subtype:\033[0m\t\t" << parse_cpu_subtype (cpu, cpu_s) << " (0x" << std::hex << *data32 << ")" << std::endl;
            data32++;
            std::cout << "\033[0;35m\t\tFiletype:\033[0m\t\t" << parse_filetype (*data32) << " (0x" << std::hex << *data32 << ")" << std::endl;
            data32++;
            std::cout << "\033[0;35m\t\tCmds count:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
            data32++;
            std::cout << "\033[0;35m\t\tSizeof cmds:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
            data32++;
            std::cout << "\033[0;35m\t\tFlags:\033[0m\t\t\t0x" << std::hex << *data32 << std::endl;
            if (header_type == BIT64)
            {
                data32++;
                std::cout << "\033[0;35m\t\tReserved:\033[0m\t\t0x" << std::hex << *data32 << std::endl;
                buffer_pos += sizeof (struct mach_header_64);
            }
            else
            {
                buffer_pos += sizeof (struct mach_header);
            }
        }
        else
        {
            abort_obj_init ("header types from fat binary should have been identified by now!");
            return;
        }
    }
}

void macho_file_obj_t::show_segments_commands (const std::string segname)
{
    struct segment_command* seg;
    struct segment_command_64* seg64;
    struct section* sect;
    struct section_64* sect64;
    
    for (int i = 0; i < (int)get_ncmds(); i++)
    {
        if (get_type() == FAT && i == (int)get_ncmds() / 2)
            std::cout << "\t\t\t\033[0;31m*\033[0m" << std::endl;
        switch (layout.cmds[i].cmd)
        {
            case LC_SEGMENT:
                seg = (struct segment_command*) layout.cmds[i].assisting_data;
                if (segname != "all" && segname != seg->segname)
                    continue;
                std::cout << "\033[0;33m\t[ " << seg->segname << " Segment ======\n\033[0;35m\t\tSize:\033[0m\t\t0x" << std::hex <<
                seg->cmdsize << std::endl;
                std::cout << "\033[0;35m\t\tVmaddr:\033[0m\t\t0x" << std::hex << seg->vmaddr << std::endl;
                std::cout << "\033[0;35m\t\tVmsize:\033[0m\t\t0x" << std::hex << seg->vmsize << std::endl;
                std::cout << "\033[0;35m\t\tFileoff:\033[0m\t0x" << std::hex << seg->fileoff << std::endl;
                std::cout << "\033[0;35m\t\tFilesize:\033[0m\t0x" << std::hex << seg->filesize << std::endl;
                std::cout << "\033[0;35m\t\tMaxprot:\033[0m\t0x" << std::hex << seg->maxprot << std::endl;
                std::cout << "\033[0;35m\t\tInitprot:\033[0m\t0x" << std::hex << seg->initprot << std::endl;
                std::cout << "\033[0;35m\t\tNsects:\033[0m\t\t0x" << std::hex << seg->nsects << std::endl;
                std::cout << "\033[0;35m\t\tFlags:\033[0m\t\t0x" << std::hex << seg->flags << std::endl;
                if (layout.cmds[i].xdata)
                {
                    for (int j = 0; j < (int)seg->nsects; j++)
                    {
                        sect = (struct section*) layout.cmds[i].assisting_extra_data + j;
                        std::cout << "\033[0;33m\t\t[ " << sect->sectname << " Section ======\n\033[0;35m";
                        std::cout << "\033[0;35m\t\t\tAddr:\033[0m\t\t0x" << std::hex << sect->addr << std::endl;
                        std::cout << "\033[0;35m\t\t\tSize:\033[0m\t\t0x" << std::hex << sect->size << std::endl;
                        std::cout << "\033[0;35m\t\t\tOffset:\033[0m\t\t0x" << std::hex << sect->offset << std::endl;
                        std::cout << "\033[0;35m\t\t\tAlign:\033[0m\t\t2^0x" << std::hex << sect->align << std::endl;
                        std::cout << "\033[0;35m\t\t\tReloff:\033[0m\t\t0x" << std::hex << sect->reloff << std::endl;
                        std::cout << "\033[0;35m\t\t\tNreloc:\033[0m\t\t0x" << std::hex << sect->nreloc << std::endl;
                        std::cout << "\033[0;35m\t\t\tFlags:\033[0m\t\t0x" << std::hex << sect->flags << std::endl;
                        std::cout << "\033[0;35m\t\t\tReserved1:\033[0m\t0x" << std::hex << sect->reserved1 << std::endl;
                        std::cout << "\033[0;35m\t\t\tReserved2:\033[0m\t0x" << std::hex << sect->reserved2 << std::endl;
                    }
                }
                break;
            case LC_SEGMENT_64:
                seg64 = (struct segment_command_64*) layout.cmds[i].assisting_data;
                if (segname != "all" && segname != seg64->segname)
                    continue;
                std::cout << "\033[0;33m\t[ " << seg64->segname << " Segment ======\n\033[0;35m\t\tSize:\033[0m\t\t0x" << std::hex <<
                seg64->cmdsize << std::endl;
                std::cout << "\033[0;35m\t\tVmaddr:\033[0m\t\t0x" << std::hex << seg64->vmaddr << std::endl;
                std::cout << "\033[0;35m\t\tVmsize:\033[0m\t\t0x" << std::hex << seg64->vmsize << std::endl;
                std::cout << "\033[0;35m\t\tFileoff:\033[0m\t0x" << std::hex << seg64->fileoff << std::endl;
                std::cout << "\033[0;35m\t\tFilesize:\033[0m\t0x" << std::hex << seg64->filesize << std::endl;
                std::cout << "\033[0;35m\t\tMaxprot:\033[0m\t0x" << std::hex << seg64->maxprot << std::endl;
                std::cout << "\033[0;35m\t\tInitprot:\033[0m\t0x" << std::hex << seg64->initprot << std::endl;
                std::cout << "\033[0;35m\t\tNsects:\033[0m\t\t0x" << std::hex << seg64->nsects << std::endl;
                std::cout << "\033[0;35m\t\tFlags:\033[0m\t\t0x" << std::hex << seg64->flags << std::endl;
                if (layout.cmds[i].xdata)
                {
                    for (int j = 0; j < (int)seg64->nsects; j++)
                    {
                        sect64 = (struct section_64*) layout.cmds[i].assisting_extra_data + j;
                        std::cout << "\033[0;33m\t\t[ " << sect64->sectname << " Section ======\n\033[0;35m";
                        std::cout << "\033[0;35m\t\t\tAddr:\033[0m\t\t0x" << std::hex << sect64->addr << std::endl;
                        std::cout << "\033[0;35m\t\t\tSize:\033[0m\t\t0x" << std::hex << sect64->size << std::endl;
                        std::cout << "\033[0;35m\t\t\tOffset:\033[0m\t\t0x" << std::hex << sect64->offset << std::endl;
                        std::cout << "\033[0;35m\t\t\tAlign:\033[0m\t\t2^0x" << std::hex << sect64->align << std::endl;
                        std::cout << "\033[0;35m\t\t\tReloff:\033[0m\t\t0x" << std::hex << sect64->reloff << std::endl;
                        std::cout << "\033[0;35m\t\t\tNreloc:\033[0m\t\t0x" << std::hex << sect64->nreloc << std::endl;
                        std::cout << "\033[0;35m\t\t\tFlags:\033[0m\t\t0x" << std::hex << sect64->flags << std::endl;
                        std::cout << "\033[0;35m\t\t\tReserved1:\033[0m\t0x" << std::hex << sect64->reserved1 << std::endl;
                        std::cout << "\033[0;35m\t\t\tReserved2:\033[0m\t0x" << std::hex << sect64->reserved2 << std::endl;
                        std::cout << "\033[0;35m\t\t\tReserved3:\033[0m\t0x" << std::hex << sect64->reserved3 << std::endl;
                    }
                }
                break;
            default:
                continue;
        }
    }
}

const int macho_file_obj_t::match_mlc_index (const std::string mlc_string)
{
    for (int i = 0; i < _SCMLC; i++)
    {
        if (mlc_string == mlc[i].name)
            return i;
        else
        {
            for (std::vector<std::string>::iterator j = mlc[i].tags.begin (); j < mlc[i].tags.end (); ++j)
            {
                if (mlc_string == *j)
                    return i;
            }
        }
    }
    return -1;
}

void macho_file_obj_t::show_mach_load_command (const int mlc_index)
{
    if (mlc_index >= _SCMLC)
    {
        std::cout << "\033[0;31msomething wrong happened, invalid index value!\n\033[0m";
        return;
    }
    else if (mlc_index == -1)
    {
        std::cout << "\033[0;31munknown load command!\n\033[0m";
        return;
    }
    
    uint32_t target_cmd = 0x0;
    int match_counter = 0, match_index = -1;
    for (int i = 0; i < (int)get_ncmds(); i++)
    {
        switch (mlc_index)
        {
            case 0:
                switch (layout.cmds[i].cmd)
            {
                case LC_ID_DYLIB:
                    target_cmd = LC_ID_DYLIB;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_LOAD_DYLIB:
                    target_cmd = LC_LOAD_DYLIB;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_LOAD_WEAK_DYLIB:
                    target_cmd = LC_LOAD_WEAK_DYLIB;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_REEXPORT_DYLIB:
                    target_cmd = LC_REEXPORT_DYLIB;
                    match_counter += 1;
                    match_index = i;
                    break;
            }
                break;
            case 1:
                if (layout.cmds[i].cmd == LC_SYMTAB)
                {
                    target_cmd = LC_SYMTAB;
                    match_counter += 1;
                    match_index = i;
                }
                break;
            case 2:
                if (layout.cmds[i].cmd == LC_DYSYMTAB)
                {
                    target_cmd = LC_DYSYMTAB;
                    match_counter += 1;
                    match_index = i;
                }
                break;
            case 3:
                switch (layout.cmds[i].cmd)
            {
                case LC_VERSION_MIN_MACOSX:
                    target_cmd = LC_VERSION_MIN_MACOSX;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_VERSION_MIN_IPHONEOS:
                    target_cmd = LC_VERSION_MIN_IPHONEOS;
                    match_counter += 1;
                    match_index = i;
                    break;
            }
                break;
            case 4:
                switch (layout.cmds[i].cmd)
            {
                case LC_DYLD_INFO:
                    target_cmd = LC_DYLD_INFO;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_DYLD_INFO_ONLY:
                    target_cmd = LC_DYLD_INFO_ONLY;
                    match_counter += 1;
                    match_index = i;
                    break;
            }
                break;
            case 5:
                switch (layout.cmds[i].cmd)
            {
                case LC_CODE_SIGNATURE:
                    target_cmd = LC_CODE_SIGNATURE;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_SEGMENT_SPLIT_INFO:
                    target_cmd = LC_SEGMENT_SPLIT_INFO;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_FUNCTION_STARTS:
                    target_cmd = LC_FUNCTION_STARTS;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_DATA_IN_CODE:
                    target_cmd = LC_DATA_IN_CODE;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_DYLIB_CODE_SIGN_DRS:
                    target_cmd = LC_DYLIB_CODE_SIGN_DRS;
                    match_counter += 1;
                    match_index = i;
                    break;
            }
                break;
            case 6:
                switch (layout.cmds[i].cmd)
            {
                case LC_ID_DYLINKER:
                    target_cmd = LC_ID_DYLINKER;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_LOAD_DYLINKER:
                    target_cmd = LC_LOAD_DYLINKER;
                    match_counter += 1;
                    match_index = i;
                    break;
                case LC_DYLD_ENVIRONMENT:
                    target_cmd = LC_DYLD_ENVIRONMENT;
                    match_counter += 1;
                    match_index = i;
                    break;
            }
                break;
        }
    }
    
    if (match_index == -1)
    {
        std::cout << "\033[0;31mload command not found in binary!\n\033[0m";
        return;
    }
    if (match_counter > 1)
    {
        std::cout << "\033[0;31mThere was more than one match, only showing last result found\n\033[0m";
    }
    std::cout << "\033[0;33m\t[ " << mlc[mlc_index].name << " Command ( 0x" << std::hex << target_cmd << " )======\n";
    char* buffer_position = (char*)((uint32_t*) layout.cmds[match_index].assisting_data + 1);
    int dati;
    uint8_t datu8;
    uint16_t datu16;
    uint32_t datu32;
    uint64_t datu64;
    for (int i = 0; i < mlc[mlc_index].nfields; i++)
    {
        switch (mlc[mlc_index].fields[i].field_type)
        {
            case INT:
                dati = *(int*) buffer_position;
                buffer_position = (char*)((int*) buffer_position + 1);
                std::cout << "\033[0;35m\t\t" << mlc[mlc_index].fields[i].name << "\033[0m " << dati << std::endl;
                break;
            case U8:
                datu8 = *(uint8_t*) buffer_position;
                buffer_position = (char*)((uint8_t*) buffer_position + 1);
                std::cout << "\033[0;35m\t\t" << mlc[mlc_index].fields[i].name << "\033[0m 0x" << std::hex << datu8 << std::endl;
                break;
            case U16:
                datu16 = *(uint16_t*) buffer_position;
                buffer_position = (char*)((uint16_t*) buffer_position + 1);
                std::cout << "\033[0;35m\t\t" << mlc[mlc_index].fields[i].name << "\033[0m 0x" << std::hex << datu16 << std::endl;
                break;
            case U32:
                datu32 = *(uint32_t*) buffer_position;
                buffer_position = (char*)((uint32_t*) buffer_position + 1);
                std::cout << "\033[0;35m\t\t" << mlc[mlc_index].fields[i].name << "\033[0m 0x" << std::hex << datu32 << std::endl;
                break;
            case U64:
                datu64 = *(uint64_t*) buffer_position;
                buffer_position = (char*)((uint64_t*) buffer_position + 1);
                std::cout << "\033[0;35m\t\t" << mlc[mlc_index].fields[i].name << "\033[0m 0x" << std::hex << datu64 << std::endl;
                break;
        }
    }
}

std::string macho_file_obj_t::parse_cpu_type (cpu_type_t cpu)
{
    if (cpu == CPU_TYPE_ANY)
        return "Any";
    else if (cpu == CPU_TYPE_VAX)
        return "VAX";
    else if (cpu == CPU_TYPE_MC680x0)
        return "MC680x0";
    else if (cpu == CPU_TYPE_X86)
        return "x86";
    else if (cpu == CPU_TYPE_I386)
        return "i386";
    else if (cpu == CPU_TYPE_X86_64)
        return "x86_64";
    else if (cpu == CPU_TYPE_MC98000)
        return "MC98000";
    else if (cpu == CPU_TYPE_HPPA)
        return "HPPA";
    else if (cpu == CPU_TYPE_ARM)
        return "ARM";
    else if (cpu == CPU_TYPE_MC88000)
        return "MC88000";
    else if (cpu == CPU_TYPE_SPARC)
        return "SPARC";
    else if (cpu == CPU_TYPE_I860)
        return "i860";
    else if (cpu == CPU_TYPE_POWERPC)
        return "PowerPC";
    else if (cpu == CPU_TYPE_POWERPC64)
        return "PowerPC64";
    return "Could not be determined";
}

std::string macho_file_obj_t::parse_cpu_subtype (cpu_type_t cpu, cpu_subtype_t cpu_s)
{

    if (cpu == CPU_TYPE_ANY) {
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_MULTIPLE:
                return "Multiple";
                break;
            case CPU_SUBTYPE_LITTLE_ENDIAN:
                return "Little Endian";
                break;
            case CPU_SUBTYPE_BIG_ENDIAN:
                return "Big Endian";
                break;
        }
    } else if (cpu == CPU_TYPE_VAX) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_VAX_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_VAX780:
                return "VAX780";
                break;
            case CPU_SUBTYPE_VAX785:
                return "VAX785";
                break;
            case CPU_SUBTYPE_VAX750:
                return "VAX750";
                break;
            case CPU_SUBTYPE_VAX730:
                return "VAX730";
                break;
            case CPU_SUBTYPE_UVAXI:
                return "UVAXI";
                break;
            case CPU_SUBTYPE_UVAXII:
                return "UVAXII";
                break;
            case CPU_SUBTYPE_VAX8200:
                return "VAX8200";
                break;
            case CPU_SUBTYPE_VAX8500:
                return "VAX8500";
                break;
            case CPU_SUBTYPE_VAX8600:
                return "VAX8600";
                break;
            case CPU_SUBTYPE_VAX8650:
                return "VAX8650";
                break;
            case CPU_SUBTYPE_VAX8800:
                return "VAX8800";
                break;
            case CPU_SUBTYPE_UVAXIII:
                return "UVAXIII";
                break;
        }
        
    } else if (cpu == CPU_TYPE_MC680x0) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_MC680x0_ALL:
                return "All";
                break;
                /*else if (cpu_s == CPU_SUBTYPE_MC68030)
                 return "MC68030";*/ // <- see <mach/machine.h>
            case CPU_SUBTYPE_MC68040:
                return "MC68040";
                break;
            case CPU_SUBTYPE_MC68030_ONLY:
                return "MC68030";
                break;
        }
        
    } else if (cpu == CPU_TYPE_X86 ||
               cpu == CPU_TYPE_X86_64) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_X86_ALL:
            /*case CPU_SUBTYPE_X86_64_ALL:  <- duplicated value, same as prev*/
                return "All";
                break;
            case CPU_SUBTYPE_X86_ARCH1:
                return "x86 ARCH1";
                break;
        }
        
    } else if (cpu == CPU_TYPE_I386) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_I386_ALL:
                return "All";
                break;
                /*case CPU_SUBTYPE_386:
                 return "386";
                 break;*/
            case CPU_SUBTYPE_486:
                return "486";
                break;
            case CPU_SUBTYPE_486SX:
                return "486SX";
                break;
                /*case CPU_SUBTYPE_586:
                 return "586";
                 break;*/
            case CPU_SUBTYPE_PENT:
                return "Pentium";
                break;
            case CPU_SUBTYPE_PENTPRO:
                return "Pentium PRO";
                break;
            case CPU_SUBTYPE_PENTII_M3:
                return "Pentium II M3";
                break;
            case CPU_SUBTYPE_PENTII_M5:
                return "Pentium II M5";
                break;
            case CPU_SUBTYPE_CELERON:
                return "Celeron";
                break;
            case CPU_SUBTYPE_CELERON_MOBILE:
                return "Celeron Mobile";
                break;
            case CPU_SUBTYPE_PENTIUM_3:
                return "Pentium 3";
                break;
            case CPU_SUBTYPE_PENTIUM_3_M:
                return "Pentium 3 M";
                break;
            case CPU_SUBTYPE_PENTIUM_3_XEON:
                return "Pentium 3 XEON";
                break;
            case CPU_SUBTYPE_PENTIUM_M:
                return "Pentium M";
                break;
            case CPU_SUBTYPE_PENTIUM_4:
                return "Pentium 4";
                break;
            case CPU_SUBTYPE_PENTIUM_4_M:
                return "Pentium 4 M";
                break;
            case CPU_SUBTYPE_ITANIUM:
                return "Itanium";
                break;
            case CPU_SUBTYPE_ITANIUM_2:
                return "Itanium 2";
                break;
            case CPU_SUBTYPE_XEON:
                return "XEON";
                break;
            case CPU_SUBTYPE_XEON_MP:
                return "XEON MP";
                break;
        }
        
    } else if (cpu == ((cpu_type_t) 8)) { //mips
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_MIPS_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_MIPS_R2300:
                return "MIPS R2300";
                break;
            case CPU_SUBTYPE_MIPS_R2600:
                return "MIPS R2600";
                break;
            case CPU_SUBTYPE_MIPS_R2800:
                return "MIPS R2800";
                break;
            case CPU_SUBTYPE_MIPS_R2000a:
                return "MIPS R2000a";
                break;
            case CPU_SUBTYPE_MIPS_R2000:
                return "MIPS R2000";
                break;
            case CPU_SUBTYPE_MIPS_R3000a:
                return "MIPS R3000a";
                break;
            case CPU_SUBTYPE_MIPS_R3000:
                return "MIPS R3000";
                break;
        }
        
    } else if (cpu == CPU_TYPE_MC98000) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_MC98000_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_MC98601:
                return "MC98601";
                break;
        }
        
    } else if (cpu == CPU_TYPE_HPPA) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_HPPA_ALL:
                return "All";
                break;
                /*case CPU_SUBTYPE_HPPA_7100:
                 return "HPPA 71000";
                 break;*/
            case CPU_SUBTYPE_HPPA_7100LC:
                return "HPPA 71000LC";
                break;
        }
        
    } else if (cpu == CPU_TYPE_ARM) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_ARM_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_ARM_V4T:
                return "ARM v4T";
                break;
            case CPU_SUBTYPE_ARM_V6:
                return "ARM v6";
                break;
            case CPU_SUBTYPE_ARM_V5TEJ:
                return "ARM v5TEJ";
                break;
            case CPU_SUBTYPE_ARM_XSCALE:
                return "ARM XSCALE";
                break;
            case CPU_SUBTYPE_ARM_V7:
                return "ARM v7";
                break;
            case CPU_SUBTYPE_ARM_V7F:
                return "ARM v7F (Cortex 9)";
                break;
            case CPU_SUBTYPE_ARM_V7S:
                return "ARM v7S (Swift)";
                break;
            case CPU_SUBTYPE_ARM_V7K:
                return "ARM v7K (Kirkwood40)";
                break;
            case CPU_SUBTYPE_ARM_V6M:
                return "ARM v6M";
                break;
            case CPU_SUBTYPE_ARM_V7M:
                return "ARM v7M";
                break;
            case CPU_SUBTYPE_ARM_V7EM:
                return "ARM v7EM";
                break;
        }
        
    } else if (cpu == CPU_TYPE_MC88000) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_MC88000_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_MC88100:
                return "MC88100";
                break;
            case CPU_SUBTYPE_MC88110:
                return "MC88110";
                break;
        }
        
    } else if (cpu == CPU_TYPE_SPARC) {
        
        if ((cpu_s & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_SPARC_ALL)
            return "All";
        
    } else if (cpu == CPU_TYPE_I860) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_I860_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_I860_860:
                return "i860 860";
                break;
        }
        
    } else if (cpu == CPU_TYPE_POWERPC ||
               cpu == CPU_TYPE_POWERPC64) {
        
        switch (cpu_s & ~CPU_SUBTYPE_MASK) {
            case CPU_SUBTYPE_POWERPC_ALL:
                return "All";
                break;
            case CPU_SUBTYPE_POWERPC_601:
                return "PowerPC 601";
                break;
            case CPU_SUBTYPE_POWERPC_602:
                return "PowerPC 602";
                break;
            case CPU_SUBTYPE_POWERPC_603:
                return "PowerPC 603";
                break;
            case CPU_SUBTYPE_POWERPC_603e:
                return "PowerPC 603e";
                break;
            case CPU_SUBTYPE_POWERPC_603ev:
                return "PowerPC 603ev";
                break;
            case CPU_SUBTYPE_POWERPC_604:
                return "PowerPC 604";
                break;
            case CPU_SUBTYPE_POWERPC_604e:
                return "PowerPC 604e";
                break;
            case CPU_SUBTYPE_POWERPC_620:
                return "PowerPC 620";
                break;
            case CPU_SUBTYPE_POWERPC_750:
                return "PowerPC 750";
                break;
            case CPU_SUBTYPE_POWERPC_7400:
                return "PowerPC 7400";
                break;
            case CPU_SUBTYPE_POWERPC_7450:
                return "PowerPC 7450";
                break;
            case CPU_SUBTYPE_POWERPC_970:
                return "PowerPC 970";
                break;
        }
    }
    return "Could not be determined";
    
}

std::string macho_file_obj_t::parse_filetype (uint32_t filetype)
{
    if (filetype == MH_OBJECT)
        return "Relocatable Object";
    else if (filetype == MH_EXECUTE)
        return "Demand Paged Executable";
    else if (filetype == MH_FVMLIB)
        return "Fixed VM Shared Library";
    else if (filetype == MH_CORE)
        return "Core";
    else if (filetype == MH_PRELOAD)
        return "Preloaded Executable";
    else if (filetype == MH_DYLIB)
        return "Dynamically Bound Shared Library";
    else if (filetype == MH_DYLINKER)
        return "Dynamic Link Editor";
    else if (filetype == MH_BUNDLE)
        return "Dynamically Bound Bundle";
    else if (filetype == MH_DYLIB_STUB)
        return "Shared Library Stub (static linking, no contents)";
    else if (filetype == MH_DSYM)
        return "Debug symbols (companion file)";
    else if (filetype == MH_KEXT_BUNDLE)
        return "x86_64 kexts";
    
    return "Could not be determined";
    
}

uint32_t macho_file_obj_t::get_ncmds ()
{
    if (type == BIT32)
    {
        return layout.header.bit32.ncmds;
    }
    else if (type == BIT64)
    {
        return layout.header.bit64.ncmds;
    }
    else if (type == FAT)
    {
        uint32_t cmds = 0x0;
        size_t buffer_pos = 0x0;
        for (int i = 0; i < (int)layout.header.fat.head.nfat_arch; i++)
        {
            bit_type_t header_type = id_cputype (layout.header.fat.archs[i].cputype);
            if (header_type == BIT32)
            {
                struct mach_header* header32 = (struct mach_header*)((char*)layout.header.fat.specified_archs_headers + buffer_pos);
                buffer_pos += sizeof (struct mach_header);
                cmds += header32->ncmds;
            }
            else if (header_type == BIT64)
            {
                struct mach_header_64* header64 = (struct mach_header_64*)((char*)layout.header.fat.specified_archs_headers + buffer_pos);
                buffer_pos += sizeof (struct mach_header_64);
                cmds += header64->ncmds;
            }
            else
            {
                abort_obj_init ("could not id header type while getting number of cmds!");
            }
        }
        
        return cmds;
    }
    else
    {
        abort_obj_init ("something wrong happened, file type should have been determined by now!");
    }
    
    return -1;
}

uint32_t macho_file_obj_t::get_sizeof_cmds ()
{
    if (type == BIT32)
    {
        return layout.header.bit32.sizeofcmds;
    }
    else if (type == BIT64)
    {
        return layout.header.bit64.sizeofcmds;
    }
    else if (type == FAT)
    {
        uint32_t size = 0x0;
        size_t buffer_pos = 0x0;
        for (int i = 0; i < (int)layout.header.fat.head.nfat_arch; i++)
        {
            bit_type_t header_type = id_cputype (layout.header.fat.archs[i].cputype);
            if (header_type == BIT32)
            {
                struct mach_header* header32 = (struct mach_header*)((char*)layout.header.fat.specified_archs_headers + buffer_pos);
                buffer_pos += sizeof (struct mach_header);
                size += header32->sizeofcmds;
            }
            else if (header_type == BIT64)
            {
                struct mach_header_64* header64 = (struct mach_header_64*)((char*)layout.header.fat.specified_archs_headers + buffer_pos);
                buffer_pos += sizeof (struct mach_header_64);
                size += header64->sizeofcmds;
            }
            else
            {
                abort_obj_init ("could not id header type while getting size of cmds!");
            }
        }
        return size;
    }
    else
    {
        abort_obj_init ("something wrong happened, file type should have been determined by now!");
    }
    return -1;
}

#define NSECT_VAL_32    (int)(*(uint32_t*)((uint8_t*)layout.cmds[i].assisting_data + 48))
#define NSECT_VAL_64    (int)(*(uint32_t*)((uint8_t*)layout.cmds[i].assisting_data + 64))

int macho_file_obj_t::get_mach_load_commands ()
{
    file.seekg (0, file.beg);
    size_t pos = 0x0, buffer_used = 0x0, *fat_pos;
    int* fat_cmds;
    if (type == BIT32 || type == BIT64)
    {
        if (type == BIT32)
            pos += sizeof (struct mach_header);
        else
            pos += sizeof (struct mach_header_64);
        file.seekg (pos, file.cur);
    }
    else if (type == FAT)
    {
        fat_pos = (size_t*) malloc (sizeof (size_t) * layout.header.fat.head.nfat_arch);
        if (fat_pos == NULL)
        {
            abort_obj_init ("could not allocate memory for archs offsets");
            return -1;
        }
        memset (fat_pos, 0, sizeof (size_t) * layout.header.fat.head.nfat_arch);
        fat_cmds = (int*) malloc (sizeof (int) * layout.header.fat.head.nfat_arch);
        if (fat_cmds == NULL)
        {
            abort_obj_init ("could not allocate memory for fat commands counters");
            return -1;
        }
        memset (fat_pos, 0, sizeof (size_t) * layout.header.fat.head.nfat_arch);
        for (int i = 0; i < (int) layout.header.fat.head.nfat_arch; i++)
        {
            fat_pos [i] = (size_t) layout.header.fat.archs[i].offset;
            const bit_type_t head_type = id_cputype (layout.header.fat.archs[i].cputype);
            if (head_type == BIT32)
            {
                struct mach_header* header32 = (struct mach_header*)((char*)layout.header.fat.specified_archs_headers + buffer_used);
                buffer_used += sizeof (mach_header);
                fat_cmds [i] = header32->ncmds;
                fat_pos [i] += sizeof (mach_header);
            }
            else if (head_type == BIT64)
            {
                struct mach_header_64* header64 = (struct mach_header_64*)((char*)layout.header.fat.specified_archs_headers + buffer_used);
                buffer_used += sizeof (mach_header_64);
                fat_cmds [i] = header64->ncmds;
                fat_pos [i] += sizeof (mach_header_64);
            }
            else
            {
                abort_obj_init ("could not id header data type (32 or 64 bit?)");
                return -1;
            }
        }
        file.seekg (fat_pos[0], file.cur);
    }
    else
    {
        abort_obj_init ("file type should be known by now, lost it in macho_file_obj_t::get_mach_load_commands ()");
        return -1;
    }
    buffer_used = 0x0;
    int current_arch = 0;
    const int total_cmds = (int) get_ncmds ();
    for (int i = 0; i < total_cmds; i++)
    {
        if (type == FAT)
        {
            if (current_arch == 0 && i == fat_cmds [0])
            {
                current_arch += 1;
                file.seekg (0, file.beg);
                file.seekg (fat_pos [current_arch], file.cur);
            }
            else if (current_arch > 0 && i - fat_cmds [current_arch - 1] == fat_cmds [current_arch])
            {
                /*
                    in case there are more archs, currently
                    only 2 archs supported
                 */
                abort_obj_init ("only 2 archs supported!");
                return -1;
                /*
                    this is actually same as above, so when implementing
                    more archs, just join the conditions in one if statement

                current_arch += 1;
                file.seekg (0, file.beg);
                file.seekg (fat_pos [current_arch], file.cur);
                 */
            }
        }
        const size_t pos = file.tellg ();
        layout.cmds[i].cmd      = readudata <uint32_t> (/*swp*/);
        layout.cmds[i].cmdsize  = readudata <uint32_t> (/*swp*/);
        file.seekg (0, file.beg);
        file.seekg (pos, file.cur);
        switch (layout.cmds[i].cmd)
        {
            case LC_SEGMENT:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct segment_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct segment_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct segment_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct segment_command));
                if (NSECT_VAL_32 < 0)
                {
                    std::cout << "\033[0;31mbad nsect value from struct segment_command, try analyzing manually!\n\033[0m";
                    break;
                }
                if (NSECT_VAL_32 == 0)
                    break;
                if (
                    NSECT_VAL_32 * sizeof (struct section)
                          + sizeof (struct segment_command) != (int)layout.cmds[i].cmdsize
                    )
                {
                    std::cout << "\033[0;31mbad nsect value from struct segment_command, cmdsize does not match data size, try analyzing manually!\n\033[0m";
                    break;
                }
                layout.cmds[i].assisting_extra_data = (void*) malloc (NSECT_VAL_32
                                                                      * sizeof (struct section));
                if (layout.cmds[i].assisting_extra_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for structs section");
                    return -1;
                }
                memset (layout.cmds[i].assisting_extra_data, 0, NSECT_VAL_32
                                                                * sizeof (struct section));
                layout.cmds[i].xdata = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_extra_data, NSECT_VAL_32
                                                                    * sizeof (struct section));
                break;
            case LC_SYMTAB:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct symtab_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct symtab_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct symtab_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct symtab_command));
                break;
            case LC_SYMSEG:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct symseg_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct symseg_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct symseg_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct symseg_command));
                break;
            case LC_THREAD:
            case LC_UNIXTHREAD:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct thread_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct thread_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct thread_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct thread_command));
                /*
                    from here read layout.cmds[i].cmdsize of uint32_t data
                                    considered extra data
                 */
                break;
            case LC_LOADFVMLIB:
            case LC_IDFVMLIB:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct fvmlib_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct fvmlib_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct fvmlib_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct fvmlib_command));
                break;
            case LC_IDENT:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct ident_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct ident_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct ident_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct ident_command));
                break;
            case LC_FVMFILE:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct fvmfile_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct fvmfile_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct fvmfile_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct fvmfile_command));
                break;
            case LC_PREPAGE:
                std::cout << "warning: command #" << i << " is LC_PREPAGE and it is not implemented, will be ignored\n";
                break;
            case LC_DYSYMTAB:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct dysymtab_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct dysymtab_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct dysymtab_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct dysymtab_command));
                break;
            case LC_LOAD_DYLIB:
            case LC_ID_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct dylib_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct dylib_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct dylib_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct dylib_command));
                break;
            case LC_ID_DYLINKER:
            case LC_LOAD_DYLINKER:
            case LC_DYLD_ENVIRONMENT:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct dylinker_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct dylinker_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct dylinker_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct dylinker_command));
                break;
            case LC_PREBOUND_DYLIB:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct prebound_dylib_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct prebound_dylib_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct prebound_dylib_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct prebound_dylib_command));
                break;
            case LC_ROUTINES:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct routines_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct routines_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct routines_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct routines_command));
                break;
            case LC_SUB_FRAMEWORK:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct sub_framework_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct sub_framework_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct sub_framework_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct sub_framework_command));
                break;
            case LC_SUB_UMBRELLA:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct sub_umbrella_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct sub_umbrella_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct sub_umbrella_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct sub_umbrella_command));
                break;
            case LC_SUB_CLIENT:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct sub_client_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct sub_client_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct sub_client_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct sub_client_command));
                break;
            case LC_SUB_LIBRARY:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct sub_library_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct sub_library_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct sub_library_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct sub_library_command));
                break;
            case LC_TWOLEVEL_HINTS:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct twolevel_hints_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct twolevel_hints_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct twolevel_hints_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct twolevel_hints_command));
                break;
            case LC_PREBIND_CKSUM:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct prebind_cksum_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct prebind_cksum_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct prebind_cksum_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct prebind_cksum_command));
                break;
            case LC_SEGMENT_64:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct segment_command_64));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct segment_command_64");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct segment_command_64));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct segment_command_64));
                if (NSECT_VAL_64 < 0)
                {
                    std::cout << "\033[0;31mbad nsect value from struct segment_command_64, try analyzing manually!\n\033[0m";
                    break;
                }
                if (NSECT_VAL_64 == 0)
                    break;
                if (
                    NSECT_VAL_64 * sizeof (struct section_64)
                    + sizeof (struct segment_command_64) != (int)layout.cmds[i].cmdsize
                    )
                {
                    std::cout << "\033[0;31mbad nsect value from struct segment_command_64, cmdsize does not match data size, try analyzing manually!\n\033[0m";
                    break;
                }
                layout.cmds[i].assisting_extra_data = (void*) malloc (NSECT_VAL_64
                                                                      * sizeof (struct section_64));
                if (layout.cmds[i].assisting_extra_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for structs section_64");
                    return -1;
                }
                memset (layout.cmds[i].assisting_extra_data, 0, NSECT_VAL_64
                                                                * sizeof (struct section_64));
                layout.cmds[i].xdata = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_extra_data, NSECT_VAL_64
                                                                * sizeof (struct section_64));
                break;
            case LC_ROUTINES_64:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct routines_command_64));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct routines_command_64");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct routines_command_64));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (routines_command_64));
                break;
            case LC_UUID:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct uuid_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct uuid_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct uuid_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*)layout.cmds[i].assisting_data, sizeof (struct uuid_command));
                break;
            case LC_RPATH:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct rpath_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct rpath_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct rpath_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct rpath_command));
                break;
            case LC_CODE_SIGNATURE:
            case LC_SEGMENT_SPLIT_INFO:
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE:
            case LC_DYLIB_CODE_SIGN_DRS:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct linkedit_data_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct linkedit_data_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct linkedit_data_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct linkedit_data_command));
                break;
            case LC_LAZY_LOAD_DYLIB:
                std::cout << "warning: command #" << i << " is LC_LAZY_LOAD_DYLIB and it is not implemented, will be ignored\n";
                break;
            case LC_ENCRYPTION_INFO:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct encryption_info_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct encryption_info_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct encryption_info_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct encryption_info_command));
                break;
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct dyld_info_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct dyld_info_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct dyld_info_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct dyld_info_command));
                break;
            case LC_LOAD_UPWARD_DYLIB:
                std::cout << "warning: command #" << i << " is LC_LOAD_UPWARD_DYLIB and it is not implemented, will be ignored\n";
                break;
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct version_min_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct version_min_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct version_min_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct version_min_command));
                break;
            case LC_MAIN:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct entry_point_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct entry_point_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct entry_point_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct entry_point_command));
                break;
            case LC_SOURCE_VERSION:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct source_version_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct source_version_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct source_version_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct source_version_command));
                break;
            case LC_ENCRYPTION_INFO_64:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct encryption_info_command_64));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct encryption_info_command_64");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct encryption_info_command_64));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct encryption_info_command_64));
                break;
            case LC_LINKER_OPTION:
                layout.cmds[i].assisting_data = (void*) malloc (sizeof (struct linker_option_command));
                if (layout.cmds[i].assisting_data == NULL)
                {
                    abort_obj_init ("could not allocate memory for struct linker_option_command");
                    return -1;
                }
                memset (layout.cmds[i].assisting_data, 0, sizeof (struct linker_option_command));
                layout.cmds[i].data = true;
                readudatabytes
                <uint8_t>
                ((uint8_t*) layout.cmds[i].assisting_data, sizeof (struct linker_option_command));
                break;

        }
        file.seekg (0, file.beg);
        file.seekg (pos + (size_t)layout.cmds[i].cmdsize, file.cur);
    }
    _ALLOC_META |= _ALLOC_LCMDS_DATA;
    if (type == FAT)
    {
        if (!fat_pos || !fat_cmds)
        {
            abort_obj_init ("something wrong happened with some memory allocations!");
            return -1;
        }
        free (fat_pos);
        free (fat_cmds);
    }
    return 0;
}

#undef NSECT_VAL_32
#undef NSECT_VAL_64

int macho_file_obj_t::get_file_layout ()
{
    get_mach_header ();
    
    const uint32_t number_cmds = get_ncmds ();
    if ((int)number_cmds < 0)
    {
        return -1;
    }
    /*const uint32_t size_cmds = get_sizeof_cmds ();
    if ((int)size_cmds <= 0)
    {
        return -1;
    }*/
    if ((sizeof (load_command_info_t) * number_cmds) > get_file_size () ||
            (int)number_cmds <= 0)
    {
        abort_obj_init ("bad input data");
        return -1;
    }
    
    layout.cmds = (load_command_info_t*) malloc (sizeof (load_command_info_t) * number_cmds);
    if (layout.cmds == NULL)
    {
        abort_obj_init ("could not allocate memory for load commands structures");
        return -1;
    }
    memset (layout.cmds, 0, sizeof (load_command_info_t) * number_cmds);
    _ALLOC_META |= _ALLOC_LCMDS;
    
    get_mach_load_commands ();
    
    return 0;
}

template <typename Type>
Type macho_file_obj_t::readudata (bool swap)
{
    if (file.is_open() == false)
    {
        abort_obj_init ("file closed unexpectedly!");
        return -1;
    }
    char tmp [sizeof (Type)/* + 1*/];
    file.read (&tmp[0], sizeof (Type));
    Type* tmp_cast = reinterpret_cast <Type*> (&tmp[0]);
    const Type value = (Type) *tmp_cast;
    
    if (swap == true &&
        (typeid (Type) == typeid (uint32_t)))
        return __builtin_bswap32 (value);
    else if (swap == true)
    {
        abort_obj_init ("swapping of other than uint32_t is not implemented yet");
        return -1;
    }
    
    return value;
}

/*
    Warning: this function does not check or validate buffer's size with given size!
    Checking, validation and mem allocation are always performed before calling this
    function.
 */
template <typename data_type>
void macho_file_obj_t::readudatabytes (data_type* data_buffer, size_t size)
{
    if (size%sizeof(data_type) != 0)
    {
        /*
            given size does not align with data type size
         */
        std::cout << "\033[1;31merr:\033[0m\033[0;31m given size does not align with data type size in readudatabytes ()\n";
        std::cout << "warning: program might have a corrupt behaviour\033[0m\n";
    }
    for (size_t i = 0; i < (size_t)(size / sizeof (data_type)); i++)
    {
        *(data_buffer++) = readudata <data_type> ();
    }
}

size_t macho_file_obj_t::get_file_size ()
{
    file.seekg (0, file.end);
    return file.tellg ();
}

template <typename Type>
void macho_file_obj_t::dump_data (size_t bytes)
{

    if (bytes%sizeof(Type)!=0)
    {
        std::cout << "\033[1;31merr:\033[0m\033[0;31m given size does not align with data type size in readudatabytes ()\n";
        std::cout << "warning: program might have a corrupt behaviour\033[0m\n";
    }
    
    Type* buffer;
    buffer = (Type*) malloc (bytes);
    readudatabytes <Type> (buffer, bytes);
    for (size_t i = 0; i < (size_t)(bytes / sizeof (Type)); i++ && buffer++)
    {
        
        if (i%15==0 && i!=0 && typeid (Type) != typeid (char))
            printf ("\n");
        
        if (typeid (Type) == typeid (uint64_t))
        {
            printf ("0x%llx ", *buffer);
        }
        else if (typeid (Type) == typeid (int))
        {
            printf ("%d ", *buffer);
        }
        else if (typeid (Type) == typeid (char))
        {
            printf ("%c", *buffer);
        }
        else
        {
            printf ("0x%02x ", *buffer);
        }
    }
    //std::cout << std::endl;
}

template <typename Type>
Type macho_file_obj_t::req_data ()
{
    return readudata <Type> ();
}

void macho_file_obj_t::rewind ()
{
    file.seekg (0, file.beg);
}

/*,,~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~,,
 *||                        End of Mach-O File Obj                      ||
 *``~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~´´
 */

/*,,~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~,,
 *||                           shwass' shell                            ||
 *``~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~´´
 */

std::vector<std::string> &split (const std::string &str, char del, std::vector<std::string> &substrs) {
    std::stringstream ss (str);
    std::string item;
    while (std::getline (ss, item, del)) {
        substrs.push_back (item);
    }
    return substrs;
}

std::vector<std::string> split (const std::string &str, char del) {
    std::vector<std::string> substrs;
    split (str, del, substrs);
    return substrs;
}

typedef enum {
    FAULT = -1,
    STANDBY = 0,
    READING = 1,
    PARSING = 2,
    RESPONSE = 3,
    EXEC = 4,
    LOADING = 5,
    DONE = 6
} shell_status_t;

class shell_obj_t {
private:
    std::string prompt;
    shell_status_t status;
    std::vector <std::string> data_types;
    std::vector <std::string> commands;
    //std::vector <std::string> history;
    std::string usage_msg;
    
    macho_file_obj_t bin;
    bool bin_loaded;
    
    void init_datt ();
    void init_cmds ();
    void print_logo ();
    std::string read_input ();
    int parse_query (std::string);
    int exec_no_arg_action (std::string);
    void dump_data_type (const int, bool ojpl = false);
    void dump_struct_type (const int, const bool);
public:
    shell_obj_t (void);
    shell_status_t get_status ();
    void interact (const int);
};

#define C_KNOWN_TYPES 51
#define DATT_STRUCT_STARTPOINT 7

void shell_obj_t::init_datt ()
{
    data_types.push_back ("int");
    data_types.push_back ("char");
    data_types.push_back ("uint8_t");
    data_types.push_back ("uint16_t");
    data_types.push_back ("uint32_t");
    data_types.push_back ("uint64_t");
    data_types.push_back ("uint128_t");
    /*structs*/
    data_types.push_back ("load_command");
    data_types.push_back ("mach_header");
    data_types.push_back ("mach_header_64");
    data_types.push_back ("segment_command");
    data_types.push_back ("segment_command_64");
    data_types.push_back ("section");
    data_types.push_back ("section_64");
    data_types.push_back ("dylib_command");
    data_types.push_back ("symtab_command");
    data_types.push_back ("dysymtab_command");
    data_types.push_back ("version_min_command");
    data_types.push_back ("dyld_info_command");
    data_types.push_back ("nlist_64");
    data_types.push_back ("nlist");
    data_types.push_back ("linkedit_data_command");
    data_types.push_back ("dylinker_command");
    data_types.push_back ("uuid_command");
    data_types.push_back ("rpath_command");
    data_types.push_back ("source_version_command");
    data_types.push_back ("fvmlib");
    data_types.push_back ("fvmlib_command");
    data_types.push_back ("dylib");
    data_types.push_back ("sub_framework_command");
    data_types.push_back ("sub_client_command");
    data_types.push_back ("sub_umbrella_command");
    data_types.push_back ("sub_library_command");
    data_types.push_back ("prebound_dylib_command");
    data_types.push_back ("routines_command");
    data_types.push_back ("routines_command_64");
    data_types.push_back ("dylib_table_of_contents");
    data_types.push_back ("dylib_module");
    data_types.push_back ("dylib_module_64");
    data_types.push_back ("dylib_reference");
    data_types.push_back ("twolevel_hints_command");
    data_types.push_back ("twolevel_hint");
    data_types.push_back ("prebind_cksum_command");
    data_types.push_back ("encryption_info_command");
    data_types.push_back ("encryption_info_command_64");
    data_types.push_back ("linker_option_command");
    data_types.push_back ("symseg_command");
    data_types.push_back ("ident_command");
    data_types.push_back ("fvmfile_command");
    data_types.push_back ("entry_point_command");
    data_types.push_back ("data_in_code_entry");
    data_types.push_back ("tlv_descriptor");
}

enum {
    OFFSET = 0,
    CLEAR = 1,
    DISASS = 2,
    DISPLAY = 3,
    EXIT = 4,
    GOTO = 5,
    HELP = 6,
    LOAD = 7,
    PRINT = 8,
    REWIND = 9,
    SHOW = 10,
    UNLOAD = 11,
} index_commands_t;

void shell_obj_t::init_cmds ()
{
    commands.push_back ("@");
    commands.push_back ("clear");
    commands.push_back ("disass");
    commands.push_back ("display");
    commands.push_back ("exit");
    commands.push_back ("goto");
    commands.push_back ("help");
    commands.push_back ("load");
    commands.push_back ("print");
    commands.push_back ("rewind");
    commands.push_back ("show");
    commands.push_back ("unload");
}

void shell_obj_t::print_logo ()
{
    std::cout <<
    "\033[0m··············\033[1;31m,~,\033[0m···················································\n"\
    "·····\033[1;31m._____.\033[0m·\033[1;31m(###è\033[0m··················································\n" \
    "····\033[1;31m/#######\033[0m·\033[1;31m`###´\033[0m····································\033[1;31m______" \
    "\033[0m··\033[1;31m______\n\033[0m···\033[1;31mé##é`¨¨´\033[0m···\033[1;31mé##\\__\033[0m···\033[1;31m__" \
    "_\033[0m···········\033[1;31m___\033[0m··\033[1;31m.-----.\033[0m·\033[1;31m_\033[0m··\033[1;31m/######"  \
    "\033[0m·\033[1;31m/######\n\033[0m···\033[1;31m##é####è,\033[0m··\033[1;31mè#é###è.\033[0m·\033[1;31m\\#" \
    "#è\033[0m·········\033[1;31mé##/\033[0m·\033[1;31mé##!¨!#èé#è\033[0m·\033[1;31m##é`¨¨´\033[0m·\033[1;31m" \
    "##é`¨¨´\n\033[0m···\033[1;31m`#!#!#!##è\033[0m·\033[1;31mé#é~´`##\033[0m··\033[1;31m`##\\\033[0m··\033[1" \
    ";31m.ô.\033[0m··\033[1;31m/##´\033[0m·\033[1;31mé###|\033[0m·\033[1;31m|####!\033[0m·\033[1;31m`!#è~~.\033" \
    "[0m·\033[1;31m`!#è~~.\n\033[0m··\033[1;31m__\033[0m···\033[1;31m.~é##´\033[0m·\033[1;31mé##\033[0m···"  \
    "\033[1;31m##\033[0m···\033[1;31m`##\\é###è/##´\033[0m··\033[1;31m####|\033[0m·\033[1;31m|####!\033[0m·\033" \
    "[1;31m__\033[0m··\033[1;31mè##\033[0m·\033[1;31m__\033[0m··\033[1;31mè##\n\033[0m·\033[1;31mé#è~é####´" \
    "\033[0m··\033[1;31mé##é\033[0m··\033[1;31m.##è\033[0m···\033[1;31m`####'####´\033[0m···\033[1;31m\\###è~" \
    "é####!\033[0m·\033[1;31mé#è~###\033[0m·\033[1;31mé#è~###\n\033[0m·\033[1;31m`######´\033[0m····\033[1;31" \
    "m`~#´\033[0m··\033[1;31m`###\033[0m·····\033[1;31m`#´\033[0m·\033[1;31m`#´\033[0m······\033[1;31m`!####!" \
    "´`#´\033[0m·\033[1;31m`#####´\033[0m·\033[1;31m`#####´\n\033[2;32m======================================" \
    "=============================\033[2;36m v 1.0\n\033[0m";
}

shell_obj_t::shell_obj_t (void)
{
    init_datt ();
    init_cmds ();
    usage_msg =
    "@          display current offset position of file\n" \
    "clear      clear screen\n" \
    "exit       exit application\n" \
    "goto       set file offset to given value\n" \
    "help       display this message\n" \
    "load       load a mach-o binary file\n" \
    "print      dump data from binary file\n" \
    "rewind     set binary file offset to 0x0\n" \
    "show       show specified data\n" \
    "unload     unload a mach-o binary file\n";
    prompt = "\033[0;36mshwass>\033[0m ";
    status = STANDBY;
    print_logo ();
    bin_loaded = false;
}

shell_status_t shell_obj_t::get_status ()
{
    return status;
}

void shell_obj_t::interact (const int thread)
{
    status = STANDBY;
    std::cout << prompt;
    bin_loaded = bin.yes;
    const std::string query = read_input ();
    if (query == "")
        return;
    parse_query (query);
}

std::string shell_obj_t::read_input ()
{
    status = READING;
    std::string query;
    std::getline (std::cin, query);
    /*if (query != "")
        history.push_back (query);*/
    return query;
}

void shell_obj_t::dump_data_type (const int index, bool ojpl)
{
    switch (index)
    {
        case INT:
            bin.dump_data <int> (1*sizeof(int));
            if (!ojpl) std::cout << std::endl;
            break;
        case CHAR:
            bin.dump_data <char> (1*sizeof(char));
            if (!ojpl) std::cout << std::endl;
            break;
        case U8:
            bin.dump_data <uint8_t> (1*sizeof(uint8_t));
            if (!ojpl) std::cout << std::endl;
            break;
        case U16:
            bin.dump_data <uint16_t> (1*sizeof(uint16_t));
            if (!ojpl) std::cout << std::endl;
            break;
        case U32:
            bin.dump_data <uint32_t> (1*sizeof(uint32_t));
            if (!ojpl) std::cout << std::endl;
            break;
        case U64:
            bin.dump_data <uint64_t> (1*sizeof(uint64_t));
            if (!ojpl) std::cout << std::endl;
            break;
    }
}

bool validate_str_int_input (const std::string n_input)
{
    for (int i = 0; i < n_input.size (); i++)
    {
        if (n_input[i] != '0' &&
            n_input[i] != '1' &&
            n_input[i] != '2' &&
            n_input[i] != '3' &&
            n_input[i] != '4' &&
            n_input[i] != '5' &&
            n_input[i] != '6' &&
            n_input[i] != '7' &&
            n_input[i] != '8' &&
            n_input[i] != '9'
            )
        {
            return false;
        }
    }
    return true;
}

const int digit_num (int num)
{
    int dig = 0;
    if (num <= 0)
        return 1;
    while (num)
    {
        num /= 10;
        dig++;
    }
    
    return dig;
}

int shell_obj_t::parse_query (std::string query)
{
    status = PARSING;
    for (std::vector<std::string>::iterator i = commands.begin (); i < commands.end (); ++i)
    {
        if (*i == query)
        {
            if (exec_no_arg_action (query) == 1)
            {
                return 1;
            }
            break;
        }
    }
    
    std::vector <std::string> split_query = split (query, ' ');
    bool valid_req = false;
    int index = 0, dindex = 0;
    for (std::vector<std::string>::iterator i = commands.begin (); i < commands.end (); ++i)
    {
        if (*i == split_query [0])
        {
            valid_req = true;
            break;
        }
        index += 1;
    }
    if (!valid_req)
    {
        std::cout << "\033[0;31mUnkown command!\n\033[0m";
        return -1;
    }
    valid_req = false;
    status = EXEC;
    const size_t file_size = bin.get_file_size ();
    const int max_dig_num = digit_num (file_size);
    switch (index)
    {
        case OFFSET:
            std::cout << "\033[0;31m@ command does not require argument!\n\033[0m";
            return -1;
            break;
        case CLEAR:
            std::cout << "\033[0;31mclear command does not require argument!\n\033[0m";
            return -1;
            break;
        case DISASS:
            std::cout << "\033[0;31mdisass command is not implemented yet!\n\033[0m";
            return -1;
            break;
        case DISPLAY:
            std::cout << "\033[0;31mdisplay command is not implemented yet!\n\033[0m";
            return -1;
            break;
        case EXIT:
            std::cout << "\033[0;31mexit command does not require argument!\n\033[0m";
            return -1;
            break;
        case GOTO:
            /*
                    There's a bug, obviously, here; need to check
                    what's the maximum digit number std::stoi can
                    handle, and check input against that.
             */
            if (split_query.size() != 2)
            {
                std::cout << "\033[0;31mrequires 1 arg only\n\033[0m";
                return -1;
            }
            if (!bin_loaded)
            {
                std::cout << "\033[0;31mno file loaded yet!\n\033[0m";
                return -1;
            }
            if (split_query[1][0] == '0' && split_query[1][1] == 'x')
            {
                if (split_query[1].size () > 9 || (split_query[1].size () - 2) >= max_dig_num)
                {
                    std::cout << "\033[0;31mInvalid offset!\n\033[0m";
                    return -1;
                }
                if (bin.set_file_pos (std::stoi (split_query[1], 0, 16)) == -1)
                {
                    std::cout << "\033[0;31mThere was a problem setting specified offset, maybe invalid value.\n\033[0m";
                    return -1;
                }
            }
            else
            {
                if (split_query[1].size () > 10 || validate_str_int_input (split_query[1]) == false)
                {
                    std::cout << "\033[0;31mInvalid offset!\n\033[0m";
                    return -1;
                }
                if (bin.set_file_pos (std::stoi (split_query[1])) == -1)
                {
                    std::cout << "\033[0;31mThere was a problem setting specified offset, maybe invalid value.\n\033[0m";
                    return -1;
                }
            }
            break;
        case HELP:
            std::cout << "\033[0;31mhelp command does not require argument!\n\033[0m";
            return -1;
            break;
        case LOAD:
            if (split_query.size() > 0x2)
            {
                std::cout << "\033[0;31mload command requires only 1 argument!\n\033[0m";
                return -1;
            }
            else if (split_query.size() == 1)
            {
                std::cout << "\033[0;31marg required!\n\033[0m";
                return -1;
            }
            else if (bin_loaded)
            {
                std::cout << "\033[0;31mbinary file already loaded, unload it first!\n\033[0m";
                return -1;
            }
            status = LOADING;
            bin.load_file (split_query[1]);
            if (bin.yes)
            {
                bin_loaded = true;
            }
            else
            {
                std::cout << "\033[0;31msomething wrong happened while trying to load file!\n\033[0m";
                return -1;
            }
            std::cout << "\033[3;32mfile " << split_query[1] << " successfully loaded!\n\033[0m";
            std::cout << "\033[0;34mFile Arch is:\033[0m ";
            switch (bin.get_type())
        {
            case BIT32:
                std::cout << "32-bit\n";
                break;
            case BIT64:
                std::cout << "64-bit\n";
                break;
            case FAT:
                std::cout << "Fat Binary\n";
                break;
            case FAIL:
                std::cout << "\033[0;31mUndetermined!\n";
                std::cout << "\033[1;31merr:\033[0m\033[5;31m Something wrong happened!\033[0m\n\033[1;31mFile type should have been identified by now!\n\033[0m";
                exec_no_arg_action ("exit");
                break;
        }
            break;
        case PRINT:
            if (!bin_loaded || !bin.yes)
            {
                std::cout << "\033[0;31m no file loaded yet!\n\033[0m";
                return -1;
            }
            switch (split_query.size())
        {
            case 2:
                for (std::vector<std::string>::iterator i = data_types.begin (); i < data_types.end (); ++i)
                {
                    if (*i == split_query[1])
                    {
                        valid_req = true;
                        break;
                    }
                    dindex += 1;
                }
                if (!valid_req || dindex > DATT_STRUCT_STARTPOINT - 1)
                {
                    std::cout << "\033[0;31munkown data type!\n\033[0m";
                    return -1;
                }
                dump_data_type (dindex);
                break;
            case 3:
                if (split_query[1] != "struct")
                {
                    std::cout << "\033[0;31munknown data type!\n\033[0m";
                    return -1;
                }
                for (std::vector<std::string>::iterator i = data_types.begin (); i < data_types.end (); ++i)
                {
                    if (*i == split_query[2])
                    {
                        valid_req = true;
                        break;
                    }
                    dindex += 1;
                }
                if (!valid_req || dindex < DATT_STRUCT_STARTPOINT)
                {
                    std::cout << "\033[0;31minvalid struct type\n\033[0m";
                    return -1;
                }
                dump_struct_type (dindex, false);
                break;
            case 4:
                for (std::vector<std::string>::iterator i = data_types.begin (); i < data_types.end (); ++i)
                {
                    if (*i == split_query[1])
                    {
                        valid_req = true;
                        break;
                    }
                    dindex += 1;
                }
                if (!valid_req || dindex > DATT_STRUCT_STARTPOINT - 1)
                {
                    std::cout << "\033[0;31munkown data type!\n\033[0m";
                    return -1;
                }
                if (split_query[2] != "*")
                {
                    std::cout << "\033[0;31munknown print sub-action!\n\033[0m";
                    return -1;
                }
                if (split_query[3][0] == '0' && split_query[3][1] == 'x')
                {
                    for (int i = 0; i < std::stoi (split_query[3], 0, 16); i++)
                        dump_data_type (dindex, true);
                    std::cout << std::endl;
                }
                else
                {
                    for (int i = 0; i < std::stoi (split_query[3]); i++)
                        dump_data_type (dindex, true);
                    std::cout << std::endl;
                }
                break;
            case 5:
                if (split_query[1] != "struct")
                {
                    std::cout << "\033[0;31munknown data type!\n\033[0m";
                    return -1;
                }
                for (std::vector<std::string>::iterator i = data_types.begin (); i < data_types.end (); ++i)
                {
                    if (*i == split_query[2])
                    {
                        valid_req = true;
                        break;
                    }
                    dindex += 1;
                }
                if (!valid_req || dindex < DATT_STRUCT_STARTPOINT)
                {
                    std::cout << "\033[0;31munkown struct type!\n\033[0m";
                    return -1;
                }
                if (split_query[3] != "*")
                {
                    std::cout << "\033[0;31munknown print sub-action!\n\033[0m";
                    return -1;
                }
                if (split_query[4][0] == '0' && split_query[4][1] == 'x')
                {
                    for (int i = 0; i < std::stoi (split_query[4], 0, 16); i++)
                    {
                        std::cout << "--------- [ " << i + 1 << " ] ---------\n";
                        dump_struct_type (dindex, false);
                    }
                }
                else
                {
                    for (int i = 0; i < std::stoi (split_query[4]); i++)
                    {
                        std::cout << "--------- [ " << i + 1 << " ] ---------\n";
                        dump_struct_type (dindex, false);
                    }
                }
                break;
            default:
                std::cout << "\033[0;31mwrong number of arguments!\n\033[0m";
                return -1;
        }
            break;
        case SHOW:
            /*
                    There is a weird bug hapenning here, not sure if here is the root cause;
                    apparently when loading a short named binary (maybe short sized binary)
                    calling show with an unknown arg, repetetly, will cause a sigfault.
                    Digging a little bit, I found out that it actually overflows RDI and RBX
                    registers.
             */
            if (split_query.size() != 2 && split_query.size() != 3 && split_query.size() != 4)
            {
                std::cout << "\033[0;31mbad arg number\n\033[0m";
                return -1;
            }
            if (!bin_loaded || !bin.yes)
            {
                std::cout << "\033[0;31mno file loaded yet!\n\033[0m";
                return -1;
            }
            if (split_query[1] == "pre" || split_query[1] == "pre-analysis")
            {
                std::cout << "\033[0;31mnot supported yet!\n\033[0m";
                return -1;
            }
            else if (split_query[1] == "header" || split_query[1] == "head")
            {
                status = RESPONSE;
                bin.show_macho_header ();
            }
            else if (split_query[1] == "headers" || split_query[1] == "heads")
            {
                if (bin.get_type () != FAT)
                {
                    std::cout << "\033[0;31mrequires a fat binary file!\n\033[0m";
                    return -1;
                }
                status = RESPONSE;
                bin.show_fat_macho_headers ();
            }
            else if (split_query[1] == "segments" || split_query[1] == "segs")
            {
                status = RESPONSE;
                bin.show_segments_commands ("all");
            }
            else if (split_query[2] == "segment" || split_query[2] == "seg")
            {
                status = RESPONSE;
                bin.show_segments_commands (split_query[1]);
            }
            else if (split_query[2] == "command" || split_query[2] == "cmd")
            {
                status = RESPONSE;
                bin.show_mach_load_command (bin.match_mlc_index (split_query[1]));
            }
            else if (split_query[3] == "command" || split_query[3] == "cmd")
            {
                status = RESPONSE;
                bin.show_mach_load_command (bin.match_mlc_index (split_query[1] + " " + split_query[2]));
            }
            else
            {
                std::cout << "\033[0;31munknown arg!\n\033[0m";
            }
            break;
        case UNLOAD:
            if (split_query.size() != 1)
            {
                std::cout << "\033[0;31mno args required!\n\033[0m";
                return -1;
            }
            else if (!bin_loaded || !bin.yes)
            {
                std::cout << "\033[0;31mno file loaded yet!\n\033[0m";
                return -1;
            }
            bin.unload_file ();
            bin_loaded = false;
            break;
    }
    
    return 0;
}

int shell_obj_t::exec_no_arg_action (std::string action)
{
    status = EXEC;
    if (action == "exit")
    {
        status = DONE;
        if (bin_loaded && bin.yes)
        {
            std::cout << "\033[0;33mdestroying everything....";
        }
        return 1;
    }
    else if (action == "clear")
    {
        system ("clear");
        return 1;
    }
    else if (action == "@")
    {
        if (!bin_loaded || !bin.yes)
        {
            std::cout << "\033[0;31mno file has been loaded!\n\033[0m";
            return 1;
        }
        std::cout << "0x" << std::hex << bin.get_file_pos () << std::endl;
        return 1;
    }
    else if (action == "help")
    {
        std::cout << usage_msg;
        return 1;
    }
    else if (action == "print")
    {
        if (!bin.yes)
        {
            std::cout << "\033[0;31mno file has been loaded!\n\033[0m";
            return 1;
        }
        bin.dump_data <uint8_t> (1);
        std::cout << std::endl;
        return 1;
    }
    else if (action == "rewind")
    {
        bin.rewind ();
        return 1;
    }
    
    return -1;
}

void shell_obj_t::dump_struct_type (const int index, const bool anid)
{
    std::string precond = "";
    if (anid)
    {
        precond = "\t";
    }
    switch (index)
    {
        case LOAD_COMMAND:
            std::cout << precond << "struct load_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case MACH_HEADER:
            std::cout << precond << "struct mach_header {\n";
            std::cout << precond << "\tmagic:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcpu_type:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcpu_subtype:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tfiletype:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tncmds:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsizeofcmds:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case MACH_HEADER_64:
            std::cout << precond << "struct mach_header_64 {\n";
            std::cout << precond << "\tmagic:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcpu_type:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcpu_subtype:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tfiletype:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tncmds:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsizeofcmds:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case SEGMENT_COMMAND:
            std::cout << precond << "struct segment_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsegname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\tvmaddr:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tvmsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tfileoff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tfilesize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tmaxprot:\t";
            bin.dump_data </*vm_prot_t*/uint32_t> (1*sizeof (vm_prot_t));
            std::cout << precond << "\n\tinitprot:\t";
            bin.dump_data </*vm_prot_t*/uint32_t> (1*sizeof (vm_prot_t));
            std::cout << precond << "\n\tnsects:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case SEGMENT_COMMAND_64:
            std::cout << precond << "struct segment_command_64 {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsegname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\tvmaddr:\t\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tvmsize:\t\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tfileoff:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tfilesize:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tmaxprot:\t";
            bin.dump_data </*vm_prot_t*/uint32_t> (1*sizeof (vm_prot_t));
            std::cout << precond << "\n\tinitprot:\t";
            bin.dump_data </*vm_prot_t*/uint32_t> (1*sizeof (vm_prot_t));
            std::cout << precond << "\n\tnsects:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case SECTION:
            std::cout << precond << "struct section {\n";
            std::cout << precond << "\tsectname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\tsegname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\taddr:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsize:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\toffset:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\talign:\t\t2^";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treloff:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnreloc:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved1:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved2:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case SECTION_64:
            std::cout << precond << "struct section_64 {\n";
            std::cout << precond << "\tsectname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\tsegname:\t";
            bin.dump_data <char> (16*sizeof (char));
            std::cout << precond << "\n\taddr:\t\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tsize:\t\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\toffset:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\talign:\t\t2^";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treloff:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnreloc:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tflags:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved1:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved2:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved3:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLIB_COMMAND:
            std::cout << precond << "struct dylib_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            dump_struct_type (DYLIB, true);
            std::cout << precond << "\n}\n";
            break;
        case SYMTAB_COMMAND:
            std::cout << precond << "struct symtab {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsymoff:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnsyms:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tstroff:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tstrsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYSYMTAB_COMMAND:
            std::cout << precond << "struct dysymtab_command {\n";
            std::cout << precond << "\tcmd:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tilocalsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnlocalsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiextdefsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextdefsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiundefsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnundefsym:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\ttocoff:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tntoc:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tmodtaboff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnmodtab:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\textrefsymoff\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextrefsyms:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tindirectsymoff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnindirectsyms:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\textreloff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextrel:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tlocreloff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnlocrel:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case VERSION_MIN_COMMAND:
            std::cout << precond << "struct version_min_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tversion:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tsdk:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLD_INFO_COMMAND:
            std::cout << precond << "struct dyld_info_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\trebase_off:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\trebase_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tbind_off:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tbind_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tweak_bind_off:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tweak_bind_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tlazy_bind_off:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tlazy_bind_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\texport_off:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\texport_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case NLIST_64:
            std::cout << precond << "struct nlist_64 {\n";
            std::cout << precond << "\tn_strx:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_type:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_sect:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_desc:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_value:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n}\n";
            break;
        case NLIST:
            std::cout << precond << "struct nlist {\n";
            std::cout << precond << "\tn_strx:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_type:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_sect:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_desc:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tn_value:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case LINKEDIT_DATA_COMMAND:
            std::cout << precond << "struct linkedit_data_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tdataoff:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tdatasize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLINKER_COMMAND:
            std::cout << precond << "struct dylinker_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str name {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case UUID_COMMAND:
            std::cout << precond << "struct uuid_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tuuid:\t\t0x";
            uint8_t uuid[16];
            for (int i = 0; i < 16; i++)
                uuid[i] = bin.req_data <uint8_t> ();
            for (int i = 15; i >= 0; i--)
                printf ("%02x", uuid[i]);
            std::cout << std::endl;
            break;
        case RPATH_COMMAND:
            std::cout << precond << "struct rpath_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str path {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case SOURCE_VERSION_COMMAND:
            std::cout << precond << "struct source_version_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tversion:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n}\n";
            break;
        case FVMLIB:
            std::cout << precond << "struct fvmlib {\n";
            std::cout << precond << "\tunion lc_str name {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "\tminor_version:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\theader_addr:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case FVMLIB_COMMAND:
            std::cout << precond << "struct fvmlib_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << std::endl;
            dump_struct_type (FVMLIB, true);
            std::cout << precond << "}\n";
            break;
        case DYLIB:
            std::cout << precond << "struct dylib {\n";
            std::cout << precond << "\tunion lc_str name {\n";
            std::cout << precond << "\t\toffset:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "\ttimestamp:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcurrent_version:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcompatibility_version:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case SUB_FRAMEWORK_COMMAND:
            std::cout << precond << "struct sub_framework_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str umbrella {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case SUB_CLIENT_COMMAND:
            std::cout << precond << "struct sub_client_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str client {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case SUB_UMBRELLA_COMMAND:
            std::cout << precond << "struct sub_umbrella_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str sub_umbrella {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case SUB_LIBRARY_COMMAND:
            std::cout << precond << "struct sub_library_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str sub_library {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case PREBOUND_DYLIB_COMMAND:
            std::cout << precond << "struct prebound_dylib_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str name {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "\tnmodules:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tunion lc_str linked_modules {\n";
            std::cout << precond << "\t\toffset:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\t}\n";
            std::cout << precond << "}\n";
            break;
        case ROUTINES_COMMAND:
            std::cout << precond << "struct routines_command {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tinit_address:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tinit_module:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved1:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved2:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved3:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved4:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved5:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\treserved6:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case ROUTINES_COMMAND_64:
            std::cout << precond << "struct routines_command_64 {\n";
            std::cout << precond << "\tcmd:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tcmdsize:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tinit_address:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\tinit_module:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved1:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved2:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved3:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved4:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved5:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n\treserved6:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLIB_TABLE_OF_CONTENTS:
            std::cout << precond << "struct dylib_table_of_contents {\n";
            std::cout << precond << "\tsymbol_index:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tmodule_index:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLIB_MODULE:
            std::cout << precond << "struct dylib_module {\n";
            std::cout << precond << "\tmodule_name:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiextdefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextdefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tirefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnrefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tilocalsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnlocalsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiextrel:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextrel:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiinit_iterm:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tninit_nterm:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tobjc_module_info_addr:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tobjc_module_info_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLIB_MODULE_64:
            std::cout << precond << "struct dylib_module_64 {\n";
            std::cout << precond << "\tmodule_name:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiextdefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextdefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tirefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnrefsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tilocalsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnlocalsym:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiextrel:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tnextrel:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tiinit_iterm:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tninit_nterm:\t\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tobjc_module_info_size:\t";
            bin.dump_data <uint32_t> (1*sizeof (uint32_t));
            std::cout << precond << "\n\tobjc_module_info_addr:\t";
            bin.dump_data <uint64_t> (1*sizeof (uint64_t));
            std::cout << precond << "\n}\n";
            break;
        case DYLIB_REFERENCE:
            std::cout << "\033[0;31mnot supported!\n\033[0m";
            break;
        case TWOLEVEL_HINTS_COMMAND:
            break;
        case TWOLEVEL_HINT:
            break;
        case PREBIND_CKSUM_COMMAND:
            break;
        case ENCRYPTION_INFO_COMMAND:
            break;
        case ENCRYPTION_INFO_COMMAND_64:
            break;
        case LINKER_OPTION_COMMAND:
            break;
        case SYMSEG_COMMAND:
            break;
        case IDENT_COMMAND:
            break;
        case FVMFILE_COMMAND:
            break;
        case ENTRY_POINT_COMMAND:
            break;
        case DATA_IN_CODE_ENTRY:
            break;
        case TLV_DESCRIPTOR:
            break;
    }
}

/*,,~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~,,
 *||                        End of shwass' shell                        ||
 *``~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~´´
 */

#endif
