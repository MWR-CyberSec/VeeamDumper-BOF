## Veeam Dumper BOF

A credential extraction BOF for Veeam Backup and Replication and Veeam One by Stephen Munro and Logan Kroeger from @MWRCyberSec. The BOF needs to be executed in an Admin beacon on either a Veeam One or Veeam Backup and Replication server and supports Cobalt Strike and Outflank C2.

```
tldr;
The BOF uses sqlcmd.exe/psql.exe to extract encrypted credential blobs from the database, grabs the salt from regisry and uses DPAPI to decrypt and print them.
```

I am not a skilled C developer, so I strongly suggest spawning a second beacon to run this BOF as a precaution if you are worried about the beacon crashing. I have tested against Veeam One and Veeam Backup and Replication for both PSQL and MSSQL and all of them worked.
<!-- There is also a standalone .Net implementation coming soon: https://github.com/MWR-CyberSec/ -->


### Disclaimer

The authors and contributors of this project are not liable for any illegal use of the tool. It is intended for educational and authorized security testing purposes only. Users are responsible for ensuring lawful usage.

### Usage

```
Dump credentials from Veeam. Supports PSQL and MSSQL!

Use: veeam-dumper [db type] [optional args]

	 db type (Required):	mssql, psql, auto 
	 --dbname (Optional):	if blank will try pull from registry. 
	 --exepath (Optional):	Path to sqlcmd.exe/psql.exe. If not specified will search $PATH and common locations depending on the DB type 
	 --debug (Optional):	Enables debug output
	 --veeamone (Optional):	Run VeeamOne mode

Examples:
	 veeam-dumper auto
	 veeam-dumper psql --dbname VeeamBackup2016 --exepath "C:\Program Files\pssql.exe" --debug
	 veeam-dumper mssql --debug --veeamone
```

![Example Image](/images/example.png)


### Features
The BOF can do the following:
* Supports both PSQL and MSSQL for Veeam Backup and Replication and Veeam One
* Outflank C2 (.s1.py) and Cobalt Strike (.cna)
* Has a full auto mode
* Search for the necessary sqlcmd.exe/psql.exe in common locations or specify manually
* Automatically obtain the database name and salt from registry for Veeam Backup and Replication and VeeamOne
* List where credentials are used by quering jobs in the Veeam database


### Compile from source

```
i686-w64-mingw32-gcc -c cs_veeam_dumper.c -o cs_veeam_dumper.x86.o
x86_64-w64-mingw32-gcc -c cs_veeam_dumper.c -o cs_veeam_dumper.x64.o
```

<!-- ### Resources

[MWR Blog - link](https://mwrcybersec.com) 

[MWR .NET implementation](https://github.com/MWR-CyberSec/) -->
