from idautils import *
from idc import *

#Color the Calls off-white
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
funcCalls = []
for i in heads:
    if print_insn_mnem(i) == "call":
        funcCalls.append(i)
print("Number of calls: %d" % (len(funcCalls)))
for i in funcCalls:
    set_color(i, CIC_ITEM, 0x5e4934)
#Color Anti-VM instructions Red and print their location
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
antiVM = []
for i in heads:
    if (print_insn_mnem(i) == "sidt" or print_insn_mnem(i) == "sgdt" or print_insn_mnem(i) == "sldt" or print_insn_mnem(i) == "smsw" or print_insn_mnem(i) == "str" or print_insn_mnem(i) == "in" or print_insn_mnem(i) == "cpuid"):
        antiVM.append(i)
print("Number of potential Anti-VM instructions: %d" % (len(antiVM)))
for i in antiVM:
    print("Anti-VM potential at %x" % i)
    set_color(i, CIC_ITEM, 0x5924f6)
#Color non-zeroing out xor instructions Orange
heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
xor = []
for i in heads:
    if print_insn_mnem(i) == "xor":
        if (print_operand(i,0) != print_operand(i,1)):
            xor.append(i)
print("Number of xor: %d" % (len(xor)))
for i in xor:
    set_color(i, CIC_ITEM, 0x5d374d)
