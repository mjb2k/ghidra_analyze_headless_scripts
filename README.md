This github repository was built to make useful ghidra scripts I found on the internet (particuluary ones that create bookmarks) to
be able to output to a file there findings to make them compatible with the analyzeHeadless mode. All credit belongs to the original creators.

To use the scripts simply do:

$YOUR_GHIDRA_PATH/analyzeHeadless <project path> <project name> -import <executable to import> -postScript <script_name> <path to output file> -scriptPath <path to script>

example:

analyzeHeadless /ghidra/projects tmp_project -import malware.exe -postScript analyze_headless_yara.py /ghidra/analyzed/output.txt -scriptPath /ghidra_analyze_headless_scripts/ninja_scripts