This is a fork of [debsums2](https://github.com/reox/debsums2), which is a python3 **only** version of `debsums2.py`, which was originally provided by [dw-itsecurity](http://www.dw-itsecurity.de/tools-hacks/debsums2-dpkg-integrity-check).

**Note: Not all features were tested and there might be bugs in this version!**

# integrity checker

## table of content
* [Introduction](#introduction)
* [Requirements](#requirements)
* [Testing](#testing)
* [Usage without the hashdb](#usage-without-the-hashdb)
* [Usage with the hashdb](#usage-with-the-hashdb)
* [Result codes](#result-codes)


## Introduction

integrity checker is born as an extension of debsums2, which is in turn an extended version of the file integrity check tool 'debsums'. The major difference of debsums2 to debsums is the ability to verify the md5sums online. The online verification is based on the control file within the debian packages, debsums2 uses a partial download to minimize the required traffic. Verification by a third party at a remote location is possible as well. In case of heavy paranoia or when md5sums are missing for a file, full package download and file verification is possible.

Moreover integrity_checker aims at automating integrity checks for as many parts of a system as possible, not just for deb packages.

There are 2 ways in which you can use the tool:
- [without the hashdb](#usage-without-the-hashdb), by computing on the fly the hashes on files and comparing them online.
- [with the hashdb](#usage-with-the-hashdb), by crawling the entire system (or part of it) and storing checksums in a json file, that later can be used as ground truth in order to detect if a file has been modified.

Things that can be checked:
- deb packages (inherited from debsums2)
- python libraries (new feature)

Future improvements:
- git repositories
- Arch Linux packages (ALPs, file extension: .pkg.tar.xz)
- Gentoo packages (file extension: .tbz2)
- RPM packages (file extensions: .rpm, .src.rpm)
- integrating the new features with the hashdb

## Requirements

```bash
  pip3 install urllib3
  pip3 install simplejson
  apt-get install python3-apt
```

## Testing

If you want to test the project or check out the functionalities, I suggest that you do it using the Dockerfile that is provided in this repo. This enables you to have an out of the box environment where you have everything that is needed to run the project, moreover the environment is smaller and a complete system check can be performed in a reasonable amount of time.

- build the docker
```bash
docker build -t debsums2 .
 ```

 - run the docker and mount the folder containing the script
 ```bash
 docker run --volume $PWD:/home/debsums2 -it -d --name debsums2 debsums2
 ```

 - access the docker and run command from there
 ```bash
 docker exec -it debsums2 /bin/bash
```


## Usage without the hashdb

### complete online system check

```bash
python3 debsums2.py --complete-system-check --ignore-pyc
```

This command will perform an online check of all the deb packages and all the python libraries.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are ignored when verifying hashes of the python libraries.

### complete online deb packages check
```bash
python3 debsums2.py --all-packages
```
This command will perform an online check of all the deb packages of the system.

### complete online python libraries check
```bash
python3 debsums2.py --check-all-py --ignore-pyc
```
This command will perform an online check of all the python libraries.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are.

### selective online deb packages check
```bash
python3 debsums2.py --package bash vim
```
This command will perform an online check of the files belonging to the packages bash and vim.
1 or more packages can be specified.

### selective online python libraries check
```bash
python3 debsums2.py --check-py simplejson urllib3 --ignore-pyc
```
This command will perform an online check of the files belonging to the libraries simplejson and urllib3.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are.

### changing the package managers

By default the script uses the command `pip2` and `pip3` to check for the python libraries. If you want to change this behavior you can supply your own list with the option --py-package-managers

 ```bash
 python3 debsums2.py --check-all-py --py-package-managers pip
 ```

##Usage with the hashdb

### complete system crawl

```
$ python3 debsums2.py --directory / --online --writedb
```

This will check your local system without the mount points. It is wise to delete all pyc files first (`find / -name \*.pyc -delete`).

After the run you will need to analyze the log (`debsums2.log`), look for `trustlevel=0` (changed file) and `trustlevel=1` (unknown file).



### Example 1: Single file check, offline

```
$ python3 debsums2.py --file /bin/bash

Entries read from /var/lib/dpkg/info: 12345
*
1 changes to hashdb.
No entries written to hashdb

12345 md5sums read from the directory where debian stores the package information. The md5sum matches locally. There are differences to the debsums2 storage. The debsums storage has not been saved.
```


### Example 2: Single file check, online

```
$ python3 debsums2.py --online --file /bin/bash

Entries read from /var/lib/dpkg/info: 12345
.
1 changes to hashdb.
No entries written to hashdb
```

All is well, the md5sum of `/bin/bash` matches the md5sum within the control file of the corresponding debian package on the debian server.



### Example 3: Package check, online

```
$ python3 debsums2.py --online --package bash

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



### Example 4: Package check, online with full package download

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



### Example 5: Directory check, online

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



### Example 6: Working with the hashdb

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



### Example 7: Running #6 again, adding online verification

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



### Example 8: Update the hashdb

```
$ python3 debsums2.py --update --online
```

First check `debsums2.log` for any irregularity. If you are sure you want the new status stored, run again and write to storage.

```
$ python3 debsums2.py --update --online --writedb
```

`--update` is to be run after `apt-get update`. It finds removed, added and changed files as well as changed uris.
This command only makes sense on a fully crawled system (`debsums2.py --directory=/`), since `--update` does not work on local files, but compares the dpkg cache to the hashdb.



### Example 9: Verification of md5sums stored in hashdb

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

## Result codes

The result of an integrity check is printed as a single character. Detailed information is logged into `debsums2.log`.

* verified online against debian package: dot (`.`) / `trustlevel=4`
* verified locally against debian package: star (`*`) / `trustlevel=3`
* verified locally against debsums2 md5sum library, needs `--writedb` in a previous debsums2 run: dash (`-`) / `trustlevel=2`
* not verified, probably new or changed file: plus (`+`) / `trustlevel=1`
* verification failed, see debsums2.log for info/warning: exclamation mark (`!`) / `trustlevel=0`
