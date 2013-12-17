ripPE
==========

**ripPE.py** helps you get at the data you want (aka "rip") from a Portable Exectuable (PE file). ripPE focuses on common sections and properties of PE files. Usage of this tool can help extract resources via the command line for quick triage, hash pertinent sections for grouping of similar files, and extract sections for developing more nuanced malware signatures (i.e. via YARA).

***Requires***
 * pefile
 * ssdeep
