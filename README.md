ripPE
==========

**ripPE.py** helps you get at the data you want ("rip") from a Portable Exectuable (PE). ripPE focuses on extracting common sections and properties of PE files for analysis. Usage of this tool can help extract resources via the command line for quick triage, hash pertinent sections for grouping of similar files, and extract sections for developing more nuanced malware signatures (i.e. via YARA).

### Communicating ripPE to your friends/colleagues:
 * Hey friend, you should totally rip those resources out of that malware.
 * I'm going rip the heck out of this PE file.
 * The only thing I'm going to be ripping after eating this bean burrito are optional headers from this PE file.
 * I could export/extract those sections from this file but, I'd rather rip them out.

### Requires:
 * pefile
 * ssdeep
 * sqlite3

### Help:
```
usage: ripPE.py --file=[file] --section=[all/other] --dump (optional) --into-db (optional) --session="testing"

ripPE.py - script used to rip raw structures from a PE file and list relevant
characteristics.

optional arguments:
  -h, --help            show this help message and exit
  --file RIPFILE        File to Parse
  --section {all,dos,header,iat,imports,exports,debug,sections,resources,dump_cert}
                        Section to rip!
  --dump                Dump raw data to file - when not provided only
                        metadata printed to stdout
  --into-db             Insert metadata into ripPE database
  --session SESSION_NAME
                        Session Identifier - stored in DB
```

### Usage: Single file saving raw sections to disk
```
python ripPE.py --file=reallybadmalware.exe --dump
```

### Usage: Single file but storing data in a SQLite dabase stored at dbripPE/ripPE.db
```
python ripPE.py --file=reallybadmalware.exe --dump --into-db
```

### Usage: Lots of files in a directory stored inside of a DB
```
for malware in $(ls /lotsofmalwaretobehadhere/ );do python ripPE.py --file=$malware --into-db;done
```

### sqlite3 you say?
Yes, I've joined the dark side. The serene beauty of the MySQL dolphin has been traded off for the lean, mean, fighting machine (possibly gluten-free with quinoa (or kale) sprinkled on top) sqlite3 database....may god have mercy on my soul. 

No worries for now. The tradeoff was for ultimate portability - meant to be as portable as the road warrior; the lone soul incident responder/malware researcher who needs to rip stuff out of a file and possibly find releated stuff in the same pile of unknowns....15 minutes ago.

## Future work...
This code was more or less dusted off and bound together from previous projects - it works, but there are no guarantees. My goal in the future is to have less caveats and more features that suit those doing triage.
