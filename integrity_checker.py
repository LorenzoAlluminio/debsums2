#!/usr/bin/python3
# -*- coding: latin-1 -*-
#
# debsums2 - dpkg integrity check
# Copyright (C) 2014  Roland Wenzel
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
__date__    = '2014-10-10'
__version__ = 3.0


import os
import stat
import hashlib
import sys
import argparse
import simplejson
import md5py
import urllib3
import tarfile
from io import BytesIO, StringIO
import logging
import subprocess
import zipfile
import re
import base64
import tempfile
import glob

infodir = "/var/lib/dpkg/info"
statusfile = "/var/lib/dpkg/status"

py_total_files = 0
py_trustlevel_counters = [0,0,0,0,0]
apt_trustlevel_counters = [0,0,0,0,0]
apt_total_files = 0

def parse_command_line():
    parser = argparse.ArgumentParser(
        description='Integrity checker for a Debian installation')
    parser.add_argument(
        '--complete-system-check',
        '--csc',
        help='Perform an online check of all the packages and all the python libraries',
        action='store_true')
    parser.add_argument(
        '-d',
        '--directory',
        help='Target directory for the integrity check')
    parser.add_argument(
        '-f',
        '--file',
        help='Target file for the integrity check')
    parser.add_argument(
        '-p',
        '--package',
        nargs='+',
        help='Target package for the integrity check.')
    parser.add_argument(
        '--all-packages',
        '--ap',
        help='Check the integrity of all packages',
        action='store_true')
    parser.add_argument(
        '-l',
        '--list-package',
        help='List all entries in hashdb.json for a given package. Append * to wildcard.')
    parser.add_argument(
        '-L',
        '--list-file',
        help='List the entry for a given file. Append * to wildcard.')
    parser.add_argument(
        '-r',
        '--remove-file',
        help='Remove the given file from the hashdb')
    parser.add_argument(
        '-R',
        '--remove-package',
        help='Remove all files of the given package from the hashdb')
    parser.add_argument(
        '-c',
        '--clean',
        help='Remove all non existing or duplicate files from hashdb',
        action='store_true')
    parser.add_argument(
        '-i',
        '--insane',
        help='Generate second md5sum using python code to detect library tampering',
        action='store_true')
    parser.add_argument(
        '-o',
        '--online',
        help='Fetch md5sums online from package url',
        action='store_true')
    parser.add_argument(
        '-O',
        '--online-full',
        help='Fetch online full package and calculate md5sums ',
        action='store_true')
    parser.add_argument(
        '-s',
        '--stats',
        help='Report statistics of hashdb storage',
        action='store_true')
    parser.add_argument(
        '-u',
        '--update',
        help='Check the hashdb storage for updated packages',
        action='store_true')
    parser.add_argument(
        '-v',
        '--verify-online',
        help='Verify all packages in the the hashdb online',
        action='store_true')
    parser.add_argument(
        '-w',
        '--writedb',
        help='Write changes to the hashdb storage',
        action='store_true')
    parser.add_argument(
	    '-V',
        '--version',
        help='Show version information',
        action='store_true')
    parser.add_argument(
        '--check-all-py',
        '--capy',
        help='check all the python libraries',
        action='store_true')
    parser.add_argument(
        '--check-py',
        '--cpy',
        nargs='+',
        help='check a list of python library')
    parser.add_argument(
        '--py-package-managers',
        '--ppm',
        nargs='+',
        help='set the package managers to use to check',
        default=["pip2","pip3"])
    parser.add_argument(
        '--ignore-pyc',
        '--ipyc',
        help='Ignore pyc files when checking python libraries',
        action='store_true')
    parser.add_argument(
        '--log-level',
        '--ll',
        help='Set log level (CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET)',
	    default="INFO")

    args = parser.parse_args()

    if args.complete_system_check == True:
        args.all_packages = True
        args.check_all_py = True

    if args.version:
        print("debsums2 - dpkg integrity check")
        print("Copyright (C) 2014  Roland Wenzel")
        print("Version {}".format(__version__))
        print("")
        print("This program is free software: you can redistribute it and/or modify")
        print("it under the terms of the GNU General Public License as published by")
        print("the Free Software Foundation, either version 3 of the License, or")
        print("(at your option) any later version.")
        print("")
        print("This program is distributed in the hope that it will be useful,")
        print("but WITHOUT ANY WARRANTY; without even the implied warranty of")
        print("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the")
        print("GNU General Public License for more details.")
        print("")
        print("You should have received a copy of the GNU General Public License")
        print("along with this program.  If not, see <https://www.gnu.org/licenses/>.")
        sys.exit(0)

    if not (args.directory or args.file or args.package) \
            and not (args.list_package or args.list_file or args.remove_file or args.remove_package) \
            and args.clean == False \
            and args.stats == False \
            and args.verify_online == False \
            and args.check_py is None \
            and args.check_all_py == False \
            and args.all_packages == False \
            and args.update == False:
        parser.print_help()
        sys.exit(1)
    return args


def readFile(filename):
    try:
        with open(filename, 'r') as f:
            data = f.read()
            return data
    except IOError:
        return ''


def readJSON(filename):
    try:
        with open(filename, 'r') as f:
            rList = simplejson.load(f, encoding="utf-8")
    except IOError:
        rList = []
    return rList


def writeJSON(filename, rList):
    try:
        with open(filename, 'w') as f:
            simplejson.dump(rList, f, sort_keys=True, indent=' ')
    except IOError:
        print('Failed to write ' + filename)


def md5ChecksumHL(filename):
    try:
        with open(filename, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
    except IOError:
        if(filename == "hashdb.json"):
            logging.info("hashdb.json is not found. Could not calculate md5sum.hashlib")
        else:
            logging.info(filename + ": Could not calculate md5sum.hashlib")
        return None


def md5ChecksumPY(filename):
    try:
        with open(filename, 'rb') as fh:
            m = md5py.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
    except IOError:
        logging.info(filename + ": Could not calculate md5sum.python")
        return None


def md5Checksum(blob):
    m = hashlib.md5()
    while True:
        data = blob.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


def parse_string(s):
    e = len(s) - 1
    while ((e != -1) and (s[e] == ' ')):
        e = e - 1
    return s[0:e + 1]


def parse_num(s):
    return int(s)


def parse_oct(s):
    return int(s, 8)


def parse_header(s):
    r = {}
    r['name'] = parse_string(s[0:16])
    r['date'] = parse_num(s[16:28])
    r['uid'] = parse_oct(s[28:34])
    r['gid'] = parse_oct(s[34:40])
    r['mode'] = parse_oct(s[40:48])
    r['size'] = parse_num(s[48:58])
    r['fmag'] = s[58:60]
    return r


def get_uri(aptcache, pkg):
    # get the full path on the server for a given package name
    if pkg is None:
        return None
    try:
        p = aptcache[pkg.split(':')[0]]
        return p.installed.uri

    except:
        logging.info(pkg + ": Error while checking package.")
        return None


def fetch_md5sum_online(uriList, connection):
    # fetch the control file of the packages in uriList and extract all md5sums
    md5sumsDictList = []
    for uri in uriList:
        response = connection.request(
            "GET", uri, "", {
                "Range": "bytes=%u-%u" %
                (0, 133)})
        if response.status in [200, 206]:
            start = 132
            end = parse_header(response.data[72:132])['size'] + start
            response = connection.request(
                "GET", uri, "", {
                    "Range": "bytes=%u-%u" %
                    (start, end)})
        if response.status in [200, 206]:
            try:
                with tarfile.open(mode="r:*", fileobj=BytesIO(response.data)) as tar:
                    for t in tar.getmembers():
                        if "md5sums" in t.name:
                            md5sums = tar.extractfile(t).read().decode("utf-8").splitlines()
                            if len(md5sums) > 0:
                                logging.debug("{} md5sums extracted from {}".format(len(md5sums), uri))
                            else:
                                logging.warning("No md5sums found in " + uri)
                            for m in md5sums:
                                md5Dict = dict(
                                    list(zip(['md5_online', 'filename'], m.split())))
                                md5Dict['filename'] = os.path.join(os.sep, md5Dict['filename'])
                                md5sumsDictList.append(md5Dict)
                            break
            except:
                logging.info("failed to open package while processing " + uri)
        else:
            logging.warning("Failed to read " + uri)
    return md5sumsDictList


def fetch_pkg_online(fDict, connection):
    # fetch the data file for the specified package and calculate the md5sums
    # for all files in the package
    md5DictList = []
    if not isvalidkey(fDict, 'uri', 'NotNone'):
        return md5DictList
    # try:
    logging.debug(fDict['uri'] + ": loading full package")
    response = connection.request("GET", fDict['uri'])
    logging.debug(fDict['uri'] +
                  ": Got " +
                  str(len(response.data)) +
                  " bytes.")
    version = parse_header(response.data[8:])
    control = parse_header(response.data[8 + 60 + version['size']:])
    data = parse_header(
        response.data[8 + 60 + version['size'] + 60 + (((control['size'] + 1) // 2) * 2):])
    data_start = 8 + 60 + version['size'] + \
        60 + (((control['size'] + 1) // 2) * 2) + 60
    data_end = data_start + data['size']

    try:
        tar = tarfile.open(mode="r:*", fileobj=BytesIO(response.data[data_start:data_end]))
    except:
        if isvalidkey(fDict, 'filename'):
            logging.info(
                fDict['filename'] +
                ": Error while loading " +
                fDict['uri'])
        else:
            logging.info("Error while loading " + fDict['uri'])
        return md5DictList

    for t in tar.getmembers():
        if t.isfile():
            fname = os.path.join(os.sep, os.path.normpath(t.name))
            md5DictList.append(
                {'filename': fname, 'md5_online': md5Checksum(tar.extractfile(t))})
    if len(md5DictList) == 0:
        logging.info(fDict['uri'] + ": Failed to extract files from package.")
    return md5DictList


def get_dpkginfo(infodir):
    # extract md5sums from dpkg status file
    sDictList = []
    contents = readFile(statusfile).splitlines()
    for c in contents:
        line = c.strip().split(':')
        md5line = line[0].split(' ')
        if len(line) == 2 and line[0] == "Package":
            package = line[1].strip()
        if len(md5line) == 2 and len(md5line[1]) == 32:
            if os.path.exists(md5line[0]):
                md5Dict = dict(list(zip(['filename', 'md5_info'], md5line)))
                md5Dict['package'] = package
                sDictList.append(md5Dict)
    sDictList = {s['filename']:s for s in sDictList}
    # read all available md5sums from infodir
    fDictList = []
    for dirpath, dirs, files in os.walk(infodir):
        for f in files:
            fileName, fileExtension = os.path.splitext(f)
            if fileExtension == ".md5sums":
                contents = readFile(os.path.join(dirpath, f)).splitlines()
                for c in contents:
                    md5Dict = dict(list(zip(['md5_info', 'filename'], c.split())))
                    md5Dict['filename'] = str(
                        os.path.join(
                            os.sep,
                            md5Dict['filename']))
                    md5Dict['package'] = os.path.splitext(f)[0]
                    fDictList.append(md5Dict)
            elif fileExtension == ".conffiles":
                contents = readFile(os.path.join(dirpath, f)).splitlines()
                for c in contents:
                    md5Dict = {'md5_info': None, 'filename': c}
                    md5Dict['package'] = os.path.splitext(f)[0]
                    if md5Dict['filename'] in list(sDictList.keys()):
                        md5Dict['md5_info'] = sDictList[md5Dict['filename']]['md5_info']
                    fDictList.append(md5Dict)
    return fDictList  # {package, md5_info, filename}


def merge_lists(l1, l2, key):
    merged = {}
    for item in l1 + l2:
        if item[key] in merged:
            merged[item[key]].update(item)
        else:
            merged[item[key]] = item
    return [val for (_, val) in list(merged.items())]


def dirscan(targetdir, fullscan):
    # find files in given directory. Restrict to st_dev, if not fullscan
    targetdev = os.stat(targetdir).st_dev
    workList = []
    for dirpath, dirs, files in os.walk(targetdir):
        if len(files) > 0 and (targetdev == os.stat(dirpath).st_dev or fullscan):
            logging.debug(dirpath + " entered.")
            for f in files:
                filename = str(os.path.join(dirpath, f))
                if not os.path.exists(filename):  # broken link
                    logging.info(filename + ": Error while checking.")
                elif stat.S_ISREG(os.stat(filename)[stat.ST_MODE]) and not os.path.islink(filename):
                    workList.append(filename)
    return workList


def get_stats(fDictList):
    # calculate some statistics for the hashdb
    trustlevelList = [0, 0, 0, 0, 0]
    #uSet = set([])

    c_md5_py = 0
    c_md5_info = 0
    c_md5_online = 0

    for fDict in fDictList:
        trustlevel = get_trustlevel(fDict)
        trustlevelList[trustlevel] += 1

        if 'md5_py' not in list(fDict.keys()) or fDict['md5_py'] is None:
            c_md5_py += 1
        if 'md5_info' not in list(fDict.keys()) or fDict['md5_info'] is None:
            c_md5_info += 1
        if 'md5_online' not in list(fDict.keys()) or fDict['md5_online'] is None:
            c_md5_online += 1

    print()
    print("Number of unique files in hashdb:       " + '\t' + str(len(getset(fDictList, 'filename'))))
    print("Number of unique packages in hashdb:    " + '\t' + str(len(getset(fDictList, 'package'))))
    print("Number of unique uris in hashdb:        " + '\t' + str(len(getset(fDictList, 'uri'))))
    print("Number of files with mismatched md5sums:" + '\t' + str(trustlevelList[0]))
    print("Number of files with no md5sum:         " + '\t' + str(trustlevelList[1]))
    print("Number of files with local md5sum:      " + '\t' + str(trustlevelList[2]))
    print("Number of files with md5sum in package: " + '\t' + str(trustlevelList[3]))
    print("Number of files with md5sum online:     " + '\t' + str(trustlevelList[4]))
    print("Number of empty md5sums (python):       " + '\t' + str(c_md5_py))
    print("Number of empty md5sums (dpkg):         " + '\t' + str(c_md5_info))
    print("Number of empty md5sums (online):       " + '\t' + str(c_md5_online))


def update_packages(fDictList, iDictList, aptcache):
    # to be run after apt-get update
    # finds removed, added and changed files as well as changed uris

    # find removed files (in hdList, not in iList), check if file exists,
    # remove it not existing
    fDelList = []
    iListSet = set([(d['filename'], d['package']) for d in iDictList])
    hd_package_List = extract(fDictList, 'package')
    hd_missList = [
        d for d in hd_package_List if (
            d['filename'],
            d['package']) not in iListSet]
    for hd in hd_missList:
        if not os.path.exists(hd['filename']):
            fDelList.append(hd)
            logging.info(
                hd['filename'] +
                ": File not found, removing from hashdb. Package is: " +
                hd['package'])
        else:
            logging.debug(
                hd['filename'] +
                ": File belongs to package " +
                hd['package'] +
                ", but was not found in package cache.")

    # find added files (in iList, not in hdList), check if file exists, add if
    # existing
    fAddList = []
    hd_package_Set = set([(d['filename'], d['package'])
                         for d in hd_package_List])
    i_addList = [
        d for d in iDictList if (
            d['filename'],
            d['package']) not in hd_package_Set]
    for i in i_addList:
        if os.path.exists(i['filename']):
            fAddList.append(i['filename'])
        else:
            logging.debug(
                i['filename'] +
                ": File not found on disk, belongs to package " +
                i['package'])

    # find changed files (md5_info differs between iList and hdList), check if
    # file exists, add if existing
    fChangeList = []
    hd_md5info_List = extract(fDictList, 'md5_info')
    hd_md5info_Set = set(
        [(d['filename'], d['md5_info'], d['package']) for d in hd_md5info_List])
    i_changeList = [
        d for d in iDictList if (
            d['filename'],
            d['md5_info'],
            d['package']) not in hd_md5info_Set]
    for i in i_changeList:
        if os.path.exists(i['filename']) and i['md5_info']:
            fChangeList.append(i['filename'])
        elif os.path.exists(i['filename']) and not i['md5_info']:
            logging.debug(
                i['filename'] +
                ": File has no md5sum in infodir, belongs to package " +
                i['package'])
        else:
            logging.debug(
                i['filename'] +
                ": File not found on disk, belongs to package " +
                i['package'])

    # find changed uris
    pChangeList = []
    pDisappearedList = []
    hd_uri_List = extract(fDictList, 'uri')
    hd_uri_Set = set([(d['package'], d['uri']) for d in hd_uri_List])
    for uri_stored in hd_uri_Set:
        uri_active = get_uri(aptcache, uri_stored[0])
        if uri_active != uri_stored[1]:
            if uri_active is None:
                if not uri_stored[0] in getset(fDelList, 'package'):
                    logging.debug(
                        uri_stored[0] +
                        ": Uri disappeared, probably source list has changed. " +
                        uri_stored[1])
                    pDisappearedList.append(uri_stored[0])
            else:
                logging.info(uri_stored[0] + ": Changed uri. " + uri_active)
                pChangeList.append(uri_stored[0])
    for hd in hd_package_List:
        if hd['package'] in pChangeList:
            if os.path.exists(hd['filename']):
                fChangeList.append(hd['filename'])

    return {'fDelList': fDelList, 'fChangeList': fChangeList,
            'fAddList': fAddList, 'pDisappearedList': pDisappearedList}


def getset(fDictList, key):
    tSet = set([])
    for fDict in fDictList:
        if isvalidkey(fDict, key, 'NotNone'):
            tSet.add(fDict[key])
    return tSet


def extract(fDictList, key, value=None, exactmatch=False):
    resultDictList = []
    for fDict in fDictList:
        if isvalidkey(fDict, key, 'NotNone') and value is not None:
            if exactmatch == True:
                if fDict[key] == value:
                    resultDictList.append(fDict)
            else:
                if value in fDict[key]:
                    resultDictList.append(fDict)
        elif isvalidkey(fDict, key, 'NotNone') and value is None:
            resultDictList.append(fDict)
    return resultDictList


def isvalidkey(fDictList, key, match=False):
    if fDictList and key in list(fDictList.keys()):
        if match == False:
            return True
        elif match == 'NotNone':
            if fDictList[key] is not None:
                return True
            else:
                return False
        else:
            if fDictList[key] == match:
                return True
            else:
                return False
    else:
        return False


def get_trustlevel(fDictList):
    trustlevel = 1
    if fDictList is None:
        return trustlevel
    tSet = set([])
    if isvalidkey(fDictList, 'md5_hl', 'NotNone'):
        trustlevel = 2
        tSet.add(fDictList['md5_hl'])
    if isvalidkey(fDictList, 'md5_py', 'NotNone'):
        tSet.add(fDictList['md5_py'])
    if isvalidkey(fDictList, 'md5_info', 'NotNone'):
        if trustlevel >= 2:
            trustlevel = 3
        tSet.add(fDictList['md5_info'])
    if isvalidkey(fDictList, 'md5_online', 'NotNone'):
        if trustlevel >= 2:
            trustlevel = 4
        tSet.add(fDictList['md5_online'])
    if len(tSet) > 1:
        trustlevel = 0
    return trustlevel


def eval_trustlevel(fileactive, trustlevel):
    global apt_trustlevel_counters
    global apt_total_files

    if trustlevel <= 4:
        if isvalidkey(fileactive, 'filename', 'NotNone'):
            if isvalidkey(fileactive, 'package', 'NotNone'):
                logging.info(
                    fileactive['filename'] +
                    ": trustlevel=" +
                    str(trustlevel) +
                    ", package: " +
                    fileactive['package'])
            else:
                logging.info(
                    fileactive['filename'] +
                    ": trustlevel=" +
                    str(trustlevel) +
                    ", package: unknown")
    apt_total_files += 1
    apt_trustlevel_counters[trustlevel] += 1
    if trustlevel == 4:  # md5sum online verified
        return '.'
    elif trustlevel == 3:  # md5sum from package list
        return '*'
    elif trustlevel == 2:  # md5sum hashlib only
        return '-'
    elif trustlevel == 1:  # no md5sums generated
        return '+'
    elif trustlevel == 0:  # md5sum mismatched
        return '!'


def diff_filestored_fileactive(fDict, fileactive):
    # compare active file dict with stored dict. If there are new or updated
    # entries, return them
    kList = []
    for k in list(fileactive.keys()):
        if fDict and fileactive[k]:
            if k in list(fDict.keys()):
                if not fileactive[k] == fDict[k]:
                    kList.append(k)  # update
            else:
                kList.append(k)  # new
    if len(kList) > 0:
        if isvalidkey(fileactive, 'filename', 'NotNone'):
            logging.debug(
                fileactive['filename'] +
                ": hashdb updated (" +
                ",".join(kList) +
                ")")
    return kList

def handle_downloaded_package(package_manager,py_filename,py_package,py_package_files,py_package_location,py_tmp_dir,ignore_pyc,type):
    global py_total_files
    global py_trustlevel_counters

    # build the checksum dictionary if whl or zip
    if(type == "zip" or type =="whl"):
        archive = zipfile.ZipFile(py_filename, "r")
        archive.extractall(py_tmp_dir.name)

        py_checksums_dict = {}
        for py_egg_file in archive.namelist():
            py_egg_file = py_egg_file.replace("\n","")
            if(not py_egg_file.endswith("/")):
                sha256 = hashlib.sha256()
                try:
                    with open(py_tmp_dir.name + "/" + py_egg_file, 'rb') as f:
                        while True:
                            data = f.read(8192)
                            if not data:
                                break
                            sha256.update(data)
                except:
                    logging.error(package_manager+":Error while computing the checksum of " + py_tmp_dir.name + "/" + py_egg_file)
                    continue
                if(type == "zip"):
                    py_egg_file = py_egg_file[len(py_package[0]+"-"+py_package[1]+"/"):]
                py_checksums_dict[py_egg_file] = base64.b64encode(sha256.digest(),b"-_").decode("utf-8").replace("=","")
        archive.close()

    # build the checksum dictionary if tar.gz
    if(type == "tar.gz"):
        archive = tarfile.open(name=py_filename, mode='r')
        archive.extractall(py_tmp_dir.name)

        py_checksums_dict = {}
        for py_egg_file in archive.getnames():
            if(archive.getmember(py_egg_file).isfile()):
                py_egg_file = py_egg_file.replace("\n","")
                sha256 = hashlib.sha256()
                try:
                    with open(py_tmp_dir.name + "/" + py_egg_file, 'rb') as f:
                        while True:
                            data = f.read(8192)
                            if not data:
                                break
                            sha256.update(data)
                except:
                    logging.error(package_manager+":Error while computing the checksum of " + py_tmp_dir.name + "/" + py_egg_file)
                    continue
                py_checksums_dict[py_egg_file[len(py_package[0]+"-"+py_package[1]+"/"):]] = base64.b64encode(sha256.digest(),b"-_").decode("utf-8").replace("=","")
        archive.close()


    # check each local file with the dictionary
    for py_package_file in py_package_files:
        py_full_path = os.path.abspath(py_package_location + "/" + py_package_file)
        if(ignore_pyc == True and py_full_path.endswith(".pyc")):
            continue
        py_total_files += 1
        if py_package_file in py_checksums_dict:
            sha256 = hashlib.sha256()
            try:
                with open(py_full_path, 'rb') as f:
                    while True:
                        data = f.read(8192)
                        if not data:
                            break
                        sha256.update(data)
                if py_checksums_dict[py_package_file] == base64.b64encode(sha256.digest(),b"-_").decode("utf-8").replace("=",""):
                    sys.stdout.write(".")
                    logging.info(package_manager+":"+py_full_path + ": trustlevel=4, package: " + py_package[0] + "==" + py_package[1])
                    py_trustlevel_counters[4] += 1
                else:
                    sys.stdout.write("!")
                    logging.info(package_manager+":"+py_full_path + ": trustlevel=0, package: " + py_package[0] + "==" + py_package[1])
                    py_trustlevel_counters[0] += 1
            except:
                logging.debug(package_manager+":file " + py_package_file + " found in output of "+ package_manager +" show -f " + py_package[0] + ", but not found on the local system")
                py_total_files -= 1
        else:
            sys.stdout.write("+")
            py_trustlevel_counters[1] += 1
            logging.info(package_manager+":"+py_full_path + ": trustlevel=1, package: " + py_package[0] + "==" + py_package[1])

def handle_package(package_manager,ignore_pyc,py_tmp_dir,py_package):
    # retrieve files in the local system with pip show
    py_show = subprocess.run([package_manager, '--no-python-version-warning', '--disable-pip-version-check' , 'show','-f',py_package[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if(py_show.stderr.decode('utf-8') == ""):
        py_package_files = []
        py_buf = StringIO(py_show.stdout.decode('utf-8'))
        for py_line in py_buf:
            # retrieve location of the package
            py_line_matches = re.match("Location:\s?(\S*).*",py_line)
            if py_line_matches:
                py_package_location = py_line_matches.group(1).replace("\n", "")
            # if version is not specified, retrieve it
            if py_package[1] == "":
                py_line_matches = re.match("Version:\s?(\S*).*",py_line)
                if py_line_matches:
                    py_package[1] = py_line_matches.group(1).replace("\n", "")
            # retrieve files
            py_line_matches = re.match("^([^:]*)$",py_line)
            if py_line_matches:
                py_package_files.append(py_line_matches.group(1).replace("\n", "").strip())

        py_package_version = py_package[0] + "==" + py_package[1]
        #print("\nHandling " + py_package_version)

        # if pip show doesn't find anything, reinitialize the list
        if(py_package_files[0] == "Cannot locate installed-files.txt"):
            py_package_files = []

        # try to infer additional files
        py_infferred_directories = glob.glob(py_package_location+"/"+py_package[0]+"*")
        for py_inferred_directory in py_infferred_directories:
            new_py_package_files = dirscan(py_inferred_directory,True)
            py_offset = len(py_package_location) + 1
            new_py_package_files = [py_temp[py_offset:] for py_temp in new_py_package_files]
            for new_py_package_file in new_py_package_files:
                if new_py_package_file not in py_package_files:
                    py_package_files.append(new_py_package_file)

        result = subprocess.run([package_manager, '--no-python-version-warning' , '--disable-pip-version-check' , 'download', py_package_version, "-d", py_tmp_dir.name, "--no-cache-dir",'--no-deps'], stdout=subprocess.PIPE, stderr=subprocess.PIPE )
        if(result.stderr.decode('utf-8')==""):
            py_filename = result.stdout.decode('utf-8').split("Saved ")[1].split("\n")[0]
            if(py_filename.endswith(".whl")):
                handle_downloaded_package(package_manager,py_filename,py_package,py_package_files,py_package_location,py_tmp_dir,ignore_pyc,"whl")
            if(py_filename.endswith(".tar.gz")):
                handle_downloaded_package(package_manager,py_filename,py_package,py_package_files,py_package_location,py_tmp_dir,ignore_pyc,"tar.gz")
            if(py_filename.endswith(".zip")):
                handle_downloaded_package(package_manager,py_filename,py_package,py_package_files,py_package_location,py_tmp_dir,ignore_pyc,"zip")
        else:
            logging.info(package_manager+":Cannot download package from pipy for " + py_package[0] + "==" + py_package[1] + ". skipping verification")
            #print(package_manager+":Cannot download package from pipy for " + py_package[0] + "==" + py_package[1] + ". skipping verification")
            for py_package_file in py_package_files:
                py_full_path = os.path.abspath(py_package_location + "/" + py_package_file)
                if(not py_full_path.endswith(".pyc")):
                    logging.info(py_full_path + ": trustlevel=1, package: " + py_package[0] + "==" + py_package[1])
    else:
        logging.info(package_manager+":Library " + py_package[0] +" not found on the system\n")
        #print(package_manager+":Library not found on the system " + py_package[0])


def check_py_libraries(package_manager,ignore_pyc,libraries_list=None):
    py_tmp_dir = tempfile.TemporaryDirectory(dir = "/tmp")

    if(libraries_list is None):
        # retrieve all libraries
        py_packages_strings = subprocess.run([package_manager, '--no-python-version-warning' , '--disable-pip-version-check' ,'list'], stdout=subprocess.PIPE).stdout.decode('utf-8').split("\n")[2:-1]

        py_packages = []
        for py_package in py_packages_strings:
            py_parts = py_package.split()
            py_packages.append(py_parts)

        # check files of each pip library
        for py_package in py_packages:
            handle_package(package_manager,ignore_pyc,py_tmp_dir,py_package)
    else:
        # check only the libraries that are in the list
        libraries_list = [library.split("==") for library in libraries_list]
        # if no version specified, add an empty string
        for library in libraries_list:
            if(len(library) == 1):
                library.append("")

        # check each library in the list
        for library in libraries_list:
            handle_package(package_manager,ignore_pyc,py_tmp_dir,library)

    py_tmp_dir.cleanup()

def main():
    global py_total_files
    global py_verified_files
    global py_not_verified_files
    global py_verification_failed_files
    global apt_trustlevel_counters

    args = parse_command_line()
    # set the logging level based on the command line option
    logging.basicConfig(filename="integrity_checker.log", format='%(asctime)s:%(levelname)s:%(message)s', \
    level=getattr(logging, args.log_level.upper()))
    logging.getLogger('urllib3').setLevel(getattr(logging, args.log_level.upper()))
    logging.debug("Starting integrity_checker -----------------------------")

    if args.directory is not None or args.update == True or args.file != None or args.package != None or args.all_packages == True:
        import apt
        aptcache = apt.Cache()
    if args.online or args.online_full or args.verify_online:
        connection = urllib3.PoolManager()

    md5sum_before = md5ChecksumHL('hashdb.json')
    hdList = readJSON('hashdb.json')
    if args.writedb == True:
        writeJSON('hashdb.json.bak', hdList)

    print()
    print("Result codes reminders:")
    print("dot (.) / trustlevel=4                     " + '\t' + "verified online against debian package")
    print("star (*) / trustlevel=3                    " + '\t' + "verified locally against debian package")
    print("star (-) / trustlevel=2                    " + '\t' + "verified locally against integrity_checker md5sum library, needs --writedb in a previous integrity_checker run")
    print("plus (+) / trustlevel=1                    " + '\t' + "not verified, probably new or changed file")
    print("exclamation mark (!) / trustlevel=0        " + '\t' + "verification failed, see integrity_checker.log for info/warning")
    print()

    if (args.directory or args.file or args.package) \
            or (args.list_package or args.list_file or args.remove_file or args.remove_package) \
            or args.clean == True \
            or args.stats == True \
            or args.verify_online == True \
            or args.all_packages == True \
            or args.update == True:
        for hd in hdList:
            if isvalidkey(hd, 'filename') and isinstance(hd['filename'], str):
                hd['filename'] = str(
                    os.path.join(
                        os.sep,
                        os.path.normpath(
                            hd['filename'])))

        hdDelList = []
        hdDupList = []
        # FIXME:
        # iList = sorted(get_dpkginfo(infodir))
        iList = get_dpkginfo(infodir)
        fsList = []
        changes = 0
        totalchanges = 0

    if args.list_package is not None:
        if args.list_package[-1] == "*":
            extractList = extract(
                hdList,
                'package',
                value=args.list_package[:-1],
                exactmatch=False)
        else:
            extractList = extract(
                hdList,
                'package',
                value=args.list_package,
                exactmatch=True)

        for i in extractList:
            print()
            for k in sorted(i.keys()):
                print("%s: \t%s" % (k, i[k]))
        return

    if args.list_file is not None:
        if args.list_file[-1] == "*":
            extractList = extract(
                hdList,
                'filename',
                value=args.list_file[
                    :-1],
                exactmatch=False)
        else:
            extractList = extract(
                hdList,
                'filename',
                value=args.list_file,
                exactmatch=True)
        for i in extractList:
            print()
            for k in sorted(i.keys()):
                print("%s: \t%s" % (k, i[k]))
        return

    if args.remove_file is not None:
        filestored = next(
            (hd for hd in hdList if hd['filename'] == args.remove_file),
            None)
        if filestored is not None:
            hdDelList.append(filestored)

    if args.remove_package is not None:
        for hd in hdList:
            if isvalidkey(hd, 'package', 'NotNone'):
                if hd['package'] == args.remove_package:
                    hdDelList.append(hd)

    if md5sum_before:
        print()
        print("Checksum of hashdb before read:         " + '\t' + md5sum_before)
        print("Entries read from hashdb:               " + '\t' + str(len(hdList)))
    if (args.directory or args.file or args.package) \
            or (args.list_package or args.list_file or args.remove_file or args.remove_package) \
            or args.clean == True \
            or args.stats == True \
            or args.verify_online == True \
            or args.all_packages == True \
            or args.update == True:
        print("START WORKING ON APT PACKAGES ------------------------------------")
        print()
        print("Entries read from " + infodir + ":      " + '\t' + str(len(iList)))

    if args.stats == True:
        get_stats(hdList)

    if args.clean:
        fsfullList = dirscan('/', True)
        print("Total files found on disk               " + '\t' + str(len(fsfullList)))
        fDelSet = getset(hdList, 'filename').difference(set(fsfullList))
        #print set(dirscan('/', False)).difference(getset(hdList, 'filename'))
        print("Dead entries to be expunged             " + '\t' + str(len(fDelSet)))
        hdDelList = [d for d in hdList if (d['filename']) in fDelSet]
        hdSet = getset(hdList, 'filename')
        for hd in hdList:
            if hd['filename'] in hdSet:
                hdSet.discard(hd['filename'])
            else:
                hdDupList.append(hd)
        print("Duplicate entries to be expunged:       " + '\t' + str(len(hdDupList)))

    if args.update == True:
        updateDictList = update_packages(hdList, iList, aptcache)
        print("Files to be expunged from hashdb:       " + '\t' + str(len(updateDictList['fDelList'])))
        print("Files to be added to hashdb:            " + '\t' + str(len(updateDictList['fAddList'])))
        print("Files to be changed in hashdb:          " + '\t' + str(len(updateDictList['fChangeList'])))
        print("Number of disappeared packages:         " + '\t' + str(len(updateDictList['pDisappearedList'])))
        fsList.extend(updateDictList['fAddList'])
        fsList.extend(updateDictList['fChangeList'])
        hdDelList.extend(updateDictList['fDelList'])
        fnewSet = set(fsList).difference(getset(hdList, 'filename'))

    if args.file is not None:
        if os.path.exists(args.file):
            fsList.append(args.file)
        else:
            logging.info(args.file + ": Error while checking.")
        fnewSet = set(fsList).difference(getset(hdList, 'filename'))

    if args.package is not None:
        for current_package in args.package:
            for i in extract(iList, 'package', value=current_package, exactmatch=True):
                if os.path.exists(i['filename']):
                    fsList.append(i['filename'])
            print("Total files in package " + current_package + '\t' + str(len(fsList)))
            fnewSet = set(fsList).difference(getset(hdList, 'filename'))
            print("Number of new files in package " + current_package + '\t' + str(len(fnewSet)))

    if args.all_packages == True:
        for current_package in aptcache.keys():
            for i in extract(iList, 'package', value=current_package, exactmatch=True):
                if os.path.exists(i['filename']):
                    fsList.append(i['filename'])
        print("Total files in all packages " + '\t' + str(len(fsList)))
        fnewSet = set(fsList).difference(getset(hdList, 'filename'))
        print("Number of new files in all packages "+ '\t' + str(len(fnewSet)))

    if args.directory is not None:
        fsList = sorted(dirscan(args.directory, False))
        print("Total files found in " + args.directory + '\t' + str(len(fsList)))
        fnewSet = set(fsList).difference(getset(hdList, 'filename'))
        print("Number of new files in package " + args.directory + '\t' + str(len(fnewSet)))
    exit

    if (args.directory or args.file or args.package) \
            or (args.list_package or args.list_file or args.remove_file or args.remove_package) \
            or args.clean == True \
            or args.stats == True \
            or args.verify_online == True \
            or args.all_packages == True \
            or args.update == True:
        if len(hdDelList) > 0:
            for hd in hdDelList:
                hdList.remove(hd)
                logging.debug(hd['filename'] + ": File removed from hashdb.")
                changes += 1
            if not len(fsList) and not len(hdDupList):
                print("\n" + str(changes) + " changes to hashdb.")

        if len(hdDupList) > 0:
            for hd in hdDupList:
                if hd in hdList:
                    hdList.remove(hd)
                logging.debug(hd['filename'] + ": Duplicate removed from hashdb.")
                changes += 1
            if not len(fsList):
                print("\n" + str(changes) + " changes to hashdb.")
        if len(fsList) > 0:
            md5onlineList = []
            md5onlineSet = set([])

            for f in fsList:
                sys.stdout.flush()
                trustlevel = 0
                if not f in fnewSet:
                    filestored = next(
                        (hd for hd in hdList if hd['filename'] == f),
                        None)
                    trustlevel = get_trustlevel(filestored)
                    if not isvalidkey(filestored, 'md5_hl') or filestored['md5_hl'] != md5ChecksumHL(filestored['filename']):
                        trustlevel = 0
                if f in fnewSet or trustlevel < 4 or args.update or args.package or args.file:
                    fileactive = {'filename': f}
                    fileactive.update(
                        next(
                            (i for i in iList if i['filename'] == fileactive['filename']), {
                                'md5_info': None, 'package': None}))
                    fileactive['uri'] = get_uri(aptcache, fileactive['package'])
                    fileactive['md5_hl'] = md5ChecksumHL(fileactive['filename'])
                    if args.insane == True:
                        fileactive['md5_py'] = md5ChecksumPY(
                            fileactive['filename'])
                    if args.online == True or args.online_full == True:
                        if isvalidkey(fileactive, 'uri', 'NotNone'):
                            if not fileactive['uri'] in md5onlineSet:
                                if args.online_full == True:
                                    md5onlineList.extend(
                                        fetch_pkg_online(
                                            fileactive,
                                            connection))
                                else:
                                    md5onlineList.extend(
                                        fetch_md5sum_online([fileactive['uri']], connection))
                                md5onlineSet.add(fileactive['uri'])
                            fileactive.update(
                                next(
                                    (m for m in md5onlineList if m['filename'] == fileactive['filename']), {
                                        'md5_online': None}))
                    trustlevel = get_trustlevel(fileactive)
                    if f in fnewSet:
                        hdList.append(fileactive)
                        changes += 1
                        if trustlevel == 2:
                            # new file, no matching to stored md5sum possible
                            trustlevel = 1
                    else:
                        diffList = diff_filestored_fileactive(
                            filestored,
                            fileactive)
                        for k in diffList:
                            filestored[k] = fileactive[k]
                            changes += 1
                            if trustlevel == 2 and k in ['md5_hl', 'md5_py', 'md5_info', 'md5_online']:
                                # changed file, no matching to stored md5sum
                                # possible
                                trustlevel = 1
                else:
                    fileactive = filestored
                sys.stdout.write(eval_trustlevel(fileactive, trustlevel))
                if changes == 250 and args.writedb == True:
                    writeJSON('/tmp/hashdb.json', hdList)
                    logging.debug(
                        "hashdb backup saved to /tmp with " + str(len(hdList)) + " entries")
                    totalchanges = totalchanges + changes
                    changes = 0
            print("\n" + str(totalchanges + changes) + " changes to hashdb.")
        print("\nSTATISTICS ON APT PACKAGES ---------")
        print("Total number of files analyzed: " + str(apt_total_files))
        for i in range(len(apt_trustlevel_counters)-1,-1,-1):
            print("Number of files with trustlevel = " + str(i) + " : " + str(apt_trustlevel_counters[i]))

    if args.verify_online == True:
        uriSet = getset(hdList, 'uri')
        print("Number of packages to fetch online:     " + '\t' + str(len(uriSet)))
        md5onlineList = fetch_md5sum_online(uriSet, connection)
        md5onlineList2 = extract(md5onlineList, 'md5_online')
        md5onlineSet = set([(d['filename'], d['md5_online']) for d in md5onlineList2])
        md5List = extract(hdList, 'md5_online')
        md5Set = set([(d['filename'], d['md5_online']) for d in md5List])
        md5differenceSet = md5Set.difference(md5onlineSet)
        print("Extracted md5sums from online packages: " + '\t' + str(len(md5onlineList)))
        print("Number of md5sums in hashdb:            " + '\t' + str(len(md5List)))
        print("Number of mismatched md5sums in hashdb: " + '\t' + str(len(md5differenceSet)))

        for md5difference in md5differenceSet:
            logging.warning(
                md5difference[0] +
                ": Online md5sum differs to md5sum in hashdb")

    if(args.check_all_py == True or args.check_py is not None):
        print()
        print("START WORKING ON PY PACKAGES ------------------------------------")
        print()

    if args.check_all_py == True or args.check_py is not None:
        for py_package_manager in args.py_package_managers:
            if(os.system("command -v "+ py_package_manager +" >/dev/null 2>&1") == 0):
                print("Checking "+ py_package_manager +" libraries -----")
                check_py_libraries(py_package_manager,args.ignore_pyc,args.check_py)
                print("\n")

        print("\nSTATISTICS ON PY PACKAGES ---------")
        print("Total number of files analyzed: " + str(py_total_files))
        for i in range(len(py_trustlevel_counters)-1,-1,-1):
            print("Number of files with trustlevel = " + str(i) + " : " + str(py_trustlevel_counters[i]))

    if args.writedb == True:
        writeJSON(
            'hashdb.json',
            sorted(
                hdList,
                key=lambda fsort: (
                    fsort['filename'])))
        md5sum_after = md5ChecksumHL('hashdb.json')
        if md5sum_before:
            print("Checksum of hashdb before read: " + md5sum_before)
        print("Checksum of hashdb after write: " + md5sum_after)
        print("\n" + str(len(hdList)) + " entries written to hashdb")
    else:
        print("\n" + "No entries written to hashdb")

if __name__ == '__main__':
    main()
