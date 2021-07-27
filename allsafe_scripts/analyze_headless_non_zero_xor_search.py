#search non zero xor
# @author: Allsafe
# @category: tools
import sys
from ghidra.program.model.listing import CodeUnit

def add_bookmark_comment(addr, text):
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "non zero xor", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)

#get all memory ranges
ranges = currentProgram.getMemory().getAddressRanges()
print("--------------------------------")
f.open(sys.argv[1], "w")
for r in ranges:
    begin = r.getMinAddress()
    length = r.getLength()

    ins = getInstructionAt(begin)
    while(ins==None):
        ins =  getInstructionAfter(ins)
    for i in range(length):
        mnemonic = ins.getMnemonicString()
        if mnemonic == "XOR":
            operand1 = ins.getOpObjects(0)
            operand2 = ins.getOpObjects(1)
            if operand1 != operand2:
                print("{} {}".format(ins.address, ins))
                add_bookmark_comment(ins.address, str(ins))
                f.write("bookmark text: " + str(ins) + "bookmark address: " + ins.address)
        ins =  getInstructionAfter(ins)
        while(ins==None):
            ins =  getInstructionAfter(ins)
