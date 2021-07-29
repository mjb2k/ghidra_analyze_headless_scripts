#search shellcode hashes
# @author: Allsafe
# @category: tools

import json
import sys
import __main__ as ghidra_app
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import CancelledException
from ghidra.program.model.scalar import Scalar

def add_bookmark_comment(addr, text):
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "shellcode_hash", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)

def  db_search(data):
    if isinstance(data[0], Scalar):
        decimal_data= int(str(data[0]), 16)
        try:
            return sc_hashes['symbol_hashes'][str(decimal_data)]
    	except:
            return -1

#Start
args = ghidra_app.getScriptArgs()
f = open(args[0], "r")
sc_hashes = json.load(f)
	
#get all instructions
instructions = currentProgram.getListing().getInstructions(True)

print("--------------------------------")
data = {}
data['bookmarks'] = []
for ins in instructions:
    mnemonic = ins.getMnemonicString()
    if mnemonic == "MOV":
        operand2 = ins.getOpObjects(1)
        symbol_info = db_search(operand2)
        if symbol_info != -1 and symbol_info != None:
            text = "{} {} [{}]{}".format(ins.address, sc_hashes['hash_types'][str(symbol_info['hash_type'])], sc_hashes['source_libs'][str(symbol_info['lib_key'])], symbol_info['symbol_name'])
            print(text)
            add_bookmark_comment(ins.address, text)
            data['bookmarks'].append({'Bookmark text': text, 'Bookmark address': ins.address})
    elif mnemonic == "PUSH":
        operand1 = ins.getOpObjects(0)
        symbol_info = db_search(operand1)
        if symbol_info != -1 and symbol_info != None:
            text = "{} {} [{}]{}".format(ins.address, sc_hashes['hash_types'][str(symbol_info['hash_type'])], sc_hashes['source_libs'][str(symbol_info['lib_key'])], symbol_info['symbol_name'])
            print(text)
            add_bookmark_comment(ins.address, text)
            data['bookmarks'].append({'Bookmark text': text, 'Bookmark address': ins.address})

if len(args) > 2:
    print("Only provide path to sc_hashes.json & output file")
if len(args) == 0:
    print("you must provide a path for the output file & sc_hashes.json");

print("[*] saving to: " + args[1])
outfile = open(args[1], "w")
json.dump(data, outfile)
