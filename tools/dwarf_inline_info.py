# modified from pyelftools example
# https://github.com/eliben/pyelftools/blob/master/examples/dwarf_die_tree.py

import sys

from elftools.elf.elffile import ELFFile

visited = {}
DIE_map = {}


def process_file(filename):
    print 'Processing file:', filename
    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        if not elf.has_dwarf_info():
            print('  file has no DWARF info')
            return

        dwarf_info = elf.get_dwarf_info()
        range_lists = dwarf_info.range_lists()

        for CU in dwarf_info.iter_CUs():
            top_die = CU.get_top_DIE()
            die_info_rec(range_lists, top_die)


def die_info_rec(range_lists, die, indent_level='	'):
    """ A recursive function for showing information about a DIE and its
        children.
    """
    global visited, DIE_map
    DIE_map[die.offset] = die
    child_indent = indent_level + '  '
    if die.tag == 'DW_TAG_inlined_subroutine' and 'DW_AT_entry_pc' in die.attributes:
        func_addr = die.attributes['DW_AT_entry_pc'].value
        abstract_origin = die.attributes['DW_AT_abstract_origin']
        abstract_origin = DIE_map[abstract_origin.value]
        if 'DW_AT_specification' in abstract_origin.attributes:
            specification = abstract_origin.attributes['DW_AT_specification']
            specification = DIE_map[specification.value]
            spec = specification
        else:
            spec = abstract_origin
        name = spec.attributes['DW_AT_name'].value
        """
        # Not used for now
        if 'DW_AT_linkage_name' in spec.attributes:
            linkage_name = spec.attributes['DW_AT_linkage_name'].value
            demangled_linkage_name = demangle(linkage_name, 0)
            if demangled_linkage_name:
                linkage_name = demangled_linkage_name
            name = linkage_name
        """
        if func_addr in visited:
            return
        visited[func_addr] = True
        # print 'inline', hex(func_addr), name
        ranges = die.attributes['DW_AT_ranges']
        ranges = range_lists.get_range_list_at_offset(ranges.value)
        inline_callback(die, name, ranges)
    for child in die.iter_children():
        die_info_rec(range_lists, child, child_indent)


def idc_inline_callback(die, name, ranges):
    for rng in ranges:
        start = rng.begin_offset
        end = rng.end_offset
        label_name = 'inlined_' + hex(start)[2:].rstrip('L')

        def nul(x):
            if x is None:
                return ''
            return x

        idc.MakeComm(start, nul(idc.Comment(start)) + '\n<%08x> inline function: %s' % (die.offset, name))
        if idc.GetFunctionAttr(start, idc.FUNCATTR_START) & 0xffffffff != 0xffffffff:
            idc.MakeNameEx(start, label_name, idc.SN_CHECK | idc.SN_LOCAL)
        else:
            idc.MakeName(start, label_name)
        while start < end:
            idc.SetColor(start, idc.CIC_ITEM, idc.GetColor(start, CIC_ITEM) - 0x2f0000)
            if start != rng.begin_offset and 0:
                idc.MakeComm(start, label_name)
            start += idc.ItemSize(start)


def cli_inline_callback(die, name, ranges):
    print 'Ranges for %s <%08x>' % (name, die.offset)
    for i, rng in enumerate(ranges):
        print '%03d\t %08x-%08x' % (i + 1, rng.begin_offset, rng.end_offset)
    print


if __name__ == '__main__':
    try:
        import idc

        sys.argv = ['', idc.GetInputFilePath()]
        demangle = idc.Demangle
        inline_callback = idc_inline_callback
    except ImportError:
        if len(sys.argv) < 2:
            print 'This script prints inline info for an elf binary.'
            print 'Usage: %s [elf path]' % sys.argv[0]
            exit()
        demangle = lambda x: x
        inline_callback = cli_inline_callback
    process_file(sys.argv[1])
