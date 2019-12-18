from idautils import *
from idc import *

#Color the Calls off-white
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
funcCalls = []
for i in heads:
    if GetMnem(i) == "call":
        funcCalls.append(i)
print "Number of calls: %d" % (len(funcCalls))
for i in funcCalls:
    SetColor(i, CIC_ITEM, 0xc7fdff)
#Color Anti-VM instructions Red and print their location
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
antiVM = []
for i in heads:
    if (GetMnem(i) == "sidt" or GetMnem(i) == "sgdt" or GetMnem(i) == "sldt" or GetMnem(i) == "smsw" or GetMnem(i) == "str" or GetMnem(i) == "in" or GetMnem(i) == "cpuid"):
        antiVM.append(i)
print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
for i in antiVM:
    print "Anti-VM potential at %x" % i
    SetColor(i, CIC_ITEM, 0x0000ff)
#Color non-zeroing out xor instructions Orange
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
xor = []
for i in heads:
    if GetMnem(i) == "xor":
        if (GetOpnd(i,0) != GetOpnd(i,1)):
            xor.append(i)
print "Number of xor: %d" % (len(xor))
for i in xor:
    SetColor(i, CIC_ITEM, 0x00a5ff)
