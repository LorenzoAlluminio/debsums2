This is a python3 **only** version of `debsums2.py`, which was originally provided by [dw-itsecurity](http://www.dw-itsecurity.de/tools-hacks/debsums2-dpkg-integrity-check).

**Note: Not all features were tested and there might be bugs in this
version!**




debsums2 - dpkg integrity check
===============================

Introduction
------------

debsums2 is an extended version of the file integrity check tool 'debsums'. The major difference to debsums is the ability to verify the md5sums online. The online verification is based on the control file within the debian packages, debsums2 uses a partial download to minimize the required traffic. Verification by a third party at a remote location is possible as well. In case of heavy paranoia or when md5sums are missing for a file, full package download and file verification is possible.

The software can be downloaded here: http://files.dw-itsecurity.de/debsums2.zip



Requirements
------------

You need the libraries `python3-urllib3`, `python3-simplejson` and `python3-apt` installed.

Usage
-----

```
$ python3 debsums2.py --directory / --online --writedb
```

This will check your local system without the mount points. On my system a full run takes about half an hour and finds 100.000 files from 1.500 packages. It is wise to delete all pyc files first (`find / -name \*.pyc -delete`).

After the run you will need to analyze the log (`debsums2.log`), look for `trustlevel=0` (changed file) and `trustlevel=1` (unknown file). I had some 2.000 findings in there. Half of them are files below `/usr/share/mime`, generated by `update-mime-database`. Some other findings are plasmoids, software installed locally (should be `/usr/local`) and lots of stuff below `/etc/`. As for the latter, see my rant below at example #3.



Example 1: Single file check, offline
-------------------------------------

```
$ python3 debsums2.py --file /bin/bash

Entries read from /var/lib/dpkg/info: 12345
*
1 changes to hashdb.
No entries written to hashdb

12345 md5sums read from the directory where debian stores the package information. The md5sum matches locally. There are differences to the debsums2 storage. The debsums storage has not been saved.
```


Example 2: Single file check, online
------------------------------------

```
$ python3 debsums2.py --online --file /bin/bash

Entries read from /var/lib/dpkg/info: 12345
.
1 changes to hashdb.
No entries written to hashdb
```

All is well, the md5sum of `/bin/bash` matches the md5sum within the control file of the corresponding debian package on the debian server.



Example 3: Package check, online
--------------------------------

```
$ python debsums2.py --online --package bash

Entries read from /var/lib/dpkg/info: 12345
Total files in package bash: 55
Number of new files in package bash: 55
.++++..................................................
55 changes to hashdb.
No entries written to hashdb
```

There are 55 files found within the package, none of them are in the debsums2 storage.

4 files do not have a checksum, otherwise clean. As for those 4 files: Debian in all its wisdom decided not to generate md5sums for almost all of the configuration files below `/etc` in their packages.
If you want to verify those files online, you will have to download the full packages (see next example). I suggest running this verification using `--directory=/etc --writedb` after checking and storing everything else.



Example 4: Package check, online with full package download
-----------------------------------------------------------

```
$ python3 debsums2.py --online-full --package bash

Entries read from /var/lib/dpkg/info: 12345
Total files in package bash: 55
Number of new files in package bash: 55
.!.....................................................
55 changes to hashdb.
No entries written to hashdb
```

1 file on (my) system is changed, checking `debsums2.log`:

```
INFO:root:/etc/bash.bashrc: trustlevel=0, package: bash
```

which is correct, since I did change this file.



Example 5: Directory check, online
----------------------------------

```
$ python3 debsums2.py --directory=/bin --online

Entries read from /var/lib/dpkg/info: 12345
Total files found in /bin: 121
Number of new files in package /bin: 121
.............................................................
............................................................
 121 changes to hashdb.
 No entries written to hashdb
```

debsums2 stays on the device where directory is located, it will not follow mount points.



Example 6: Working with the hashdb
----------------------------------

```
$ python3 debsums2.py --directory=/bin --writedb

Entries read from /var/lib/dpkg/info: 12345
Total files found in /bin: 121
Number of new files in package /bin: 121
*************************************************************
************************************************************
121 changes to hashdb.
Checksum of hashdb after write: f2a9acb71b91a5b0f44f6832ea81caf7
121 entries written to hashdb
```

The first run with `--writedb` will create a file `hashdb.json`, storing the md5sums and package information.
A md5sum is calculated for this file before and after the debsums2 run, you may store that value somewhere offline.

```
 {
  "filename": "/bin/bash",
  "md5_hl": "144968564a6b1159ed82059920cea76f",
  "md5_info": "144968564a6b1159ed82059920cea76f",
  "package": "bash",
  "uri": "http://security.debian.org/pool/updates/main/
  b/bash/bash_4.2+dfsg-0.1+deb7u3_amd64.deb"
 }
```



Example 7: Running #6 again, adding online verification
-------------------------------------------------------

```
$ python3 debsums2.py --directory=/bin --writedb --online

Checksum of hashdb before read: f2a9acb71b91a5b0f44f6832ea81caf7
Entries read from hashdb: 121
Entries read from /var/lib/dpkg/info: 12345
Total files found in /bin: 121
Number of new files in package /bin: 0
..............................................................
...........................................................
121 changes to hashdb.
Checksum of hashdb before read: f2a9acb71b91a5b0f44f6832ea81caf7
Checksum of hashdb after write: ea5bffb2fa69b2b086c4f0ff5727125f
121 entries written to hashdb
```

debsums2 reads the stored information for this run, all files were checked before. The hashdb contains "md5_online" for each entry after the run, the checksum for `hashdb.json` is updated.



Example 8: Update the hashdb
----------------------------

```
$ python3 debsums2.py --update --online
```

First check `debsums2.log` for any irregularity. If you are sure you want the new status stored, run again and write to storage.

```
$ python3 debsums2.py --update --online --writedb
```

`--update` is to be run after `apt-get update`. It finds removed, added and changed files as well as changed uris.
This command only makes sense on a fully crawled system (`debsums2.py --directory=/`), since `--update` does not work on local files, but compares the dpkg cache to the hashdb.



Example 9: Verification of md5sums stored in hashdb
---------------------------------------------------

```
$ python3 debsums2.py --verify-online

Checksum of hashdb before read: ea5bffb2fa69b2b086c4f0ff5727125f
Entries read from hashdb: 121
Entries read from /var/lib/dpkg/info: 12345
Number of packages to fetch online: 30
Extracted md5sums from online packages: 1493
Number of md5sums in hashdb: 121
Number of mismatched md5sums in hashdb: 0
No entries written to hashdb
```

If the number of mismatched md5sums is not null, check `debsums2.log` for details.

This command is for everybody with a high paranoia level suspecting a deeply compromized system, therefore the command can and should be run on a different system, you will need to transfer the hashdb. Be aware that the download of all control files takes some time, you can watch the progress with `tail -f debsums2.log`.



Result codes
------------

The result of an integrity check is printed as a single character. Detailed information is logged into `debsums2.log`.

* verified online against debian package: dot (`.`) / `trustlevel=4`
* verified locally against debian package: star (`*`) / `trustlevel=3`
* verified locally against debsums2 md5sum library, needs `--writedb` in a previous debsums2 run: dash (`-`) / `trustlevel=2`
* not verified, probably new of changed file: plus (`+`) / `trustlevel=1`
* verification failed, see debsums2.log for info/warning: exclamation mark (`!`) / `trustlevel=0`

