# Run binwalk on the current file and create bookmarks and EOL comments for findings.
#@author Thomas Roth code@stacksmashing.net
#@category Ghidra Ninja
#@keybinding
#@menupath
#@toolbar


import subprocess
import tempfile
import os
import csv
import json
import __main__ as ghidra_app
from ghidra.program.model.listing import CodeUnit

def add_bookmark_comment(addr, text):
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "binwalk", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)

file_location = currentProgram.getDomainFile().getMetadata()["Executable Location"]
_, result_file = tempfile.mkstemp()
data = {}
data['bookmarks'] = []
try:
	subprocess.call(["binwalk", "-c", "-f", result_file, file_location])
	with open(result_file) as csvfile:
		reader = csv.reader(csvfile, delimiter=',', quotechar='"')
		for row in reader:
			try:
				addr = currentProgram.minAddress.add(int(row[0]))
			except:
				continue

			text = row[2]
			data['bookmarks'].append({'Bookmark text': text, 'Bookmark address': addr})
			add_bookmark_comment(addr, text)
except Exception as e:
	print("Failed")
	print(e)

args = ghidra_app.getScriptArgs()
if len(args) > 1:
    print("please provide the path of the output file as the ONLY argument.")
if len(args) == 0:
    print("you must provide a path for the output file.");

print("[*] saving to: " + args[0])
outfile = open(args[0], "w")
json.dump(data, outfile)

os.unlink(result_file)
