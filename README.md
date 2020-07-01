This is a fork of [debsums2](https://github.com/reox/debsums2), which is a python3 **only** version of `debsums2.py`, which was originally provided by [dw-itsecurity](http://www.dw-itsecurity.de/tools-hacks/debsums2-dpkg-integrity-check).

**Note: Not all features were tested and there might be bugs in this version!**

# Integrity checker

## Table of content
* [Introduction](#introduction)
* [Requirements](#requirements)
* [Testing](#testing)
* [How to interpret the output](#how-to-interpret-the-output)
* [Usage without the hashdb](#usage-without-the-hashdb)
* [Usage with the hashdb](#usage-with-the-hashdb)
* [Result codes](#result-codes)
* [Troubleshooting](#troubleshooting)
* [Experimental git repo checking functionality
](#experimental-git-repo-checking-functionality)

## Introduction

integrity checker is born as an extension of debsums2, which is in turn an extended version of the file integrity check tool 'debsums'.

First in order to understand what was the purpose of debsusm2, I quote from their readme.md:
> The major difference of debsums2 to debsums is the ability to verify the md5sums online. The online verification is based on the control file within the debian packages, debsums2 uses a partial download to minimize the required traffic. Verification by a third party at a remote location is possible as well. In case of heavy paranoia or when md5sums are missing for a file, full package download and file verification is possible.

In addition to this functionality, integrity_checker aims at automating integrity checks for as many parts of a system as possible, not just for deb packages.

Things that can be checked:
- deb packages (inherited from debsums2)
- python libraries (new feature)

There are 2 ways in which you can use the tool:
- [without the hashdb](#usage-without-the-hashdb), by computing on the fly the hashes of files and comparing them online.
- [with the hashdb](#usage-with-the-hashdb), by crawling the entire system (or part of it) and storing checksums in a json file, that later can be used as ground truth in order to detect if a file has been modified/added/removed.

Future improvements:
- add support for git repositories ( an experimental version is implemented in the `git-support` branch, __but don't use it on your system, try it only in the docker for testing! It's not finished and there could be bugs that could damage your system.__)
- integrating the python libraries with the hashdb
- add support for Arch Linux packages (ALPs, file extension: .pkg.tar.xz)
- add support for Gentoo packages (file extension: .tbz2)
- add support for RPM packages (file extensions: .rpm, .src.rpm)

## Requirements

```bash
pip3 install urllib3
pip3 install simplejson
apt-get install python3-apt
```

## Testing

If you want to test the project or check out the functionalities, I suggest that you do it using the Dockerfile that is provided in this repository. This gives you a series of advantages:
- enables you to have an out of the box environment where you have everything that is needed to run the project
- a complete system check can be performed in a reasonable amount of time
- __if you are trying the experimental git repository checking functionality__, even if there is some bug in it your system won't be affected.

Steps to spin up the docker:

- build the docker
```bash
docker build -t integrity_checker .
```

- run the docker and mount the folder containing the script
```bash
docker run --volume $PWD:/home/integrity_checker -it -d --name integrity_checker integrity_checker
```

- access the docker and run command from there
```bash
docker exec -it integrity_checker /bin/bash
cd integrity_checker
```

## How to interpret the output

Both when checking deb packages or python libraries, the tool prints a series of sections:
1. a reminder of the result codes, that you can check also [here](#result-codes)
2. Then it starts verifying files and printing the corresponding symbols to screen. This enables you to see the progress of the tool and check visually if there are "weird" things (e.g. a lot of subsequent `+` symbols --> probably there is a problem verifying an entire package, such as the online location of it can't be found)
3. Statistics about the analysis the has been ran.

When the script terminates, you can then check the integrity_checker.log to look for file with different trustlevels:
```bash
cat integrity_checker.log | grep trustlevel=4
cat integrity_checker.log | grep trustlevel=3
cat integrity_checker.log | grep trustlevel=2
cat integrity_checker.log | grep trustlevel=1
cat integrity_checker.log | grep trustlevel=0
```
In this way you can restrict a lot the search for compromised files, since all the ones with trustlevel=4 are for sure unmodified.

Please keep in mind that the integrity_checker.log is not recreated at each run, the information are always appended to it. You need to be aware of it because otherwise you may merge together results of different analysis without knowing it. If you want to consider the result of a single analysis, either do some filtering on the timestamp or delete the integrity_checker.log file before starting the script.

If you want to see some example output check out the links provided for each example. The commands are run in the testing docker.

## Usage without the hashdb

Since the python libraries are checked using pip, it's better to first check the integrity of it.
The procedure is different based on how you installed pip on your system.
For the testing docker you should do:
```bash
python3 integrity_checker.py --package python-pip python3-pip --online-full
```
to check pip2 and pip3 (installed with apt).

From the output of the command we can see that every file belonging to the pip2 and pip3 packages is verified correctly. Same info is provided by the log.

[Output of the command & log](./example_outputs/01.apt_pip_pip3_of.md)

If you use the option `--py-package-managers` make sure to check the integrity of what you specify there as well.

### complete online system check

This command will perform an online check of all the deb packages and all the python libraries.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are ignored when verifying hashes of the python libraries.

```bash
python3 integrity_checker.py --complete-system-check --online --ignore-pyc
```
The complete apt check has found 88 files that are not verified online, just locally. This is because they are configuration files under /etc, whose checksums are not stored in the deb package metadata. They would be correctly verified if we ran an `online-full` analysis.

The python libraries analysis instead found 141 files that are not found online. Mostly they are some files which are detected by pip, but were installed through apt (such as pip itself) and some metadata (\*-info directories) which in the local system are under the path `*-egg-info*` while online they are under `*-dist-info*`. A possible future improvement could be to verify if this mapping is valid for all libraries and if yes, check the corresponding file.
It found also 20 files for which the verification fails. This is probably because the content of these scripts is changed based on where you install the library, but I'm not 100% sure.

[Output of the command & log](./example_outputs/02.complete_system_check.md)

### complete online full deb packages check
This command will perform an online-full check of all the deb packages of the system.

```bash
python3 integrity_checker.py --all-packages --online-full
```

Now that we ran an online-full analysis we can see that almost all the files are verified correctly online.

[Output of the command & log](./example_outputs/03.all_packages.md)

### complete online python libraries check
This command will perform an online check of all the python libraries.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are ignored.

```bash
python3 integrity_checker.py --check-all-py --ignore-pyc
```

From the output we can see that the result is the same as the complete system check one.

[Output of the command & log](./example_outputs/04.all_py.md)

### selective online deb packages check
This command will perform an online check of the files belonging to the packages bash and vim.
1 or more packages can be specified.

```bash
python3 integrity_checker.py --package bash vim --online
```
[Output of the command & log](./example_outputs/05.sel_deb.md)

### selective online python libraries check

This command will perform an online check of the files belonging to the libraries simplejson and urllib3.
Moreover the `--ignore-pyc` option will ensure that the .pyc file are.

```bash
python3 integrity_checker.py --check-py simplejson urllib3 --ignore-pyc
```

We can see the all files are verified correctly except for the file in the `*-info` directories which I mentioned earlier and the RECORD file, which is a file that contains hashes of the other file in the local system. A future improvement could be to use also this file to verify in order to save bandwidth and to be able to verify stuff locally (like the original `debsums` does).

[Output of the command & log](./example_outputs/06.sel_py.md)

### changing the package managers

By default the script uses the command `pip2` and `pip3` to check for the python libraries. If you want to change this behavior you can supply your own list with the option --py-package-managers

```bash
python3 integrity_checker.py --check-all-py --py-package-managers pip
```

Here we can see a lot of files that were not found online and that's because we didn't ignore the .pyc files.

[Output of the command & log](./example_outputs/07.change_pm.md)

### Single file check, offline

```bash
python3 integrity_checker.py --file /bin/bash
```

We can see that the package is verified locally, like the original `debsums` does.

[Output of the command & log](./example_outputs/08.sfc_off.md)
### Single file check, online

```bash
python3 integrity_checker.py --online --file /bin/bash
```

Here instead we can see that the file is verified online.

[Output of the command & log](./example_outputs/09.sfc_on.md)
### Package check, online

```bash
python3 integrity_checker.py --online --package bash
```

There are 66 files found within the package, 4 files do not have a checksum, otherwise clean. As for those 4 files: Debian decided not to generate md5sums for almost all of the configuration files below `/etc` in their packages.
If you want to verify those files online, you will have to download the full packages (see next example).

[Output of the command & log](./example_outputs/10.pkg_on.md)

### Package check, online with full package download

```bash
python3 integrity_checker.py --online-full --package bash
```

Now all files are verified online.

[Output of the command & log](./example_outputs/11.pkg_on_full.md)
### Directory check, online

integrity_checker stays on the device where directory is located, it will not follow mount points.

```bash
python3 integrity_checker.py --directory=/bin --online
```

[Output of the command & log](./example_outputs/12.dir_on.md)

## Usage with the hashdb

### complete system crawl

This will check your local system without the mount points. It is wise to delete all pyc files first (`find / -name \*.pyc -delete`).

The first run with `--writedb` will create a file `hashdb.json`, storing the md5sums and package information.
A md5sum is calculated for this file before and after the integrity_checker run, you may store that value somewhere offline.

```bash
python3 integrity_checker.py --directory / --online --writedb
```
[Output of the command & log & hashdb](./example_outputs/13.complete_crawl.md)

Example entry of the hashdb:
```bash
{
"filename": "/bin/bash",
"md5_hl": "144968564a6b1159ed82059920cea76f",
"md5_info": "144968564a6b1159ed82059920cea76f",
"package": "bash",
"uri": "http://security.debian.org/pool/updates/main/
b/bash/bash_4.2+dfsg-0.1+deb7u3_amd64.deb"
}
```

### Writing single directory to the hashdb

```bash
python3 integrity_checker.py --directory=/bin --writedb
```
[Output of the command & log & hashdb](./example_outputs/14.sd_hashdb.md)

### Writing single directory to the hashdb, adding online verification

```bash
python3 integrity_checker.py --directory=/bin --writedb --online
```
[Output of the command & log & hashdb](./example_outputs/15.sd_hashdb_on.md)

### Update the hashdb

`--update` finds removed, added and changed files as well as changed uris.
This command only makes sense on a fully crawled system (`integrity_checker.py --directory=/`), since `--update` compares the dpkg cache to the hashdb.

```bash
python3 integrity_checker.py --update --online
```

We can see that if we ran update after installing a package, it detects the changes.

[Output of the command & log](./example_outputs/16.update_hashdb.md)

First check `integrity_checker.log` for any irregularity. If you are sure you want the new status stored, run again and write to storage.

```bash
python3 integrity_checker.py --update --online --writedb
```
[Output of the command & log](./example_outputs/17.update_hashdb.md)

### Verification of md5sums stored in hashdb

This command verifies online all the hashes stored in the hashdb. If the number of mismatched md5sums is not 0, check `integrity_checker.log` for details.

```bash
python3 integrity_checker.py --verify-online
```
[Output of the command & log](./example_outputs/18.verify_hashdb.md)

## Result codes

The result of an integrity check is printed as a single character. Detailed information is logged into `integrity_checker.log`.

* verified against online hash: dot (`.`) / `trustlevel=4`
* verified against local hash in the system: star (`*`) / `trustlevel=3`
* verified against local hash in the hashdb: dash (`-`) / `trustlevel=2`
* not verified, probably new or changed file: plus (`+`) / `trustlevel=1`
* verification failed, see integrity_checker.log for info/warning: exclamation mark (`!`) / `trustlevel=0`

## Troubleshooting

if you have some errors regarding `--no-python-version-warning`, you need to upgrade pip.

## Experimental git repo checking functionality

The progress on this functionality can be seen on the `git-support` branch. I didn't merge this code into master because it is still not finished and could have some bugs that could potentially damage your system. If you want to try it, do so in the testing docker.

I'm going to do a small writeup of the problem I encountered and how I tried to solve them, what worked and what not.

1. How to find the git repos?
`find / -name ".git"` does the job.
2. Check if the repo is up to up to date
`git remote show origin | grep "(local out of date)"` does the job.
3. In which way a malware could modify a git repo for some malicious purpose?
    3.1 modify a file and leave it uncommitted
    3.2 modify a file and commit it
    3.3 modify the previous commits (the history of the repo) in such a way that the current files result modified (not sure it's feasible)
    3.4 modify the repo, install the library, undo the modification
4. How to detect those attacks?
    4.1 use git status to see if there are uncommitted changes
    4.2 compare commit history of local repo with online repo
    4.3  compare the whole ".git" folder between the local repo and the online repo.
    4.4 compare the installed files with the online reference

I implemented point 1 and 2, then I moved to implementing point 4.3.
I encountered some problems while doing so, the first one is that the `.git` directory is different even for the same repo cloned 2 times subsequently. Therefore I thought about comparing only the `.git/objects` subdirectory. This directory contains all the compresse "snapshots" taken by git. The problem now is that sometimes git packs a lot of object into a single .pack file and this causes problem when comparing because you need to check if there are .pack files and if yes unpack them, otherwise you may have 1 repo in which objects are not packed and 1 repo where objects are packed.
I tried to implement it but sometimes it works and sometimes not, therefore probably there is still something that I'm missing and I feel like I should look more deeper in how the ".git" directory works to be able to implement it in an efficient way.
