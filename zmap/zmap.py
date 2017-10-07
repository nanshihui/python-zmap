#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
zmap.py - version and date, see below

Source code : https://github.com/nanshihui/python-zmap/

Author :

* Sherwel Nan - https://github.com/nanshihui/python-zmap/



Licence : Apache License 2.0


A permissive license whose main conditions require preservation of copyright and license notices.
Contributors provide an express grant of patent rights. Licensed works, modifications, and larger
works may be distributed under different terms and without source code.




"""

__author__ = 'Sherwel Nan'
__version__ = '0.1'
__last_modification__ = '2017.07.31'

import csv
import io
import os
import re
import shlex
import subprocess
import sys

try:
    from multiprocessing import Process
except ImportError:
    from threading import Thread as Process


############################################################################


class PortScanner(object):
    """
    PortScanner class allows to use zmap from python

    """

    def __init__(self, zmap_search_path=('zmap',
                                         '/usr/bin/zmap',
                                         '/usr/local/bin/zmap',
                                         '/sw/bin/zmap',
                                         '/opt/local/bin/zmap'),Async=False,call_back=None):
        """
        Initialize PortScanner module

        * detects zmap on the system and zmap version
        * may raise PortScannerError exception if zmap is not found in the path

        :param zmap_search_path: tupple of string where to search for zmap executable. Change this if you want to use a specific version of zmap.
        :returns: nothing

        """
        self._zmap_path = ''  # zmap path
        self._scan_result = {}
        self._zmap_version_number = 0  # zmap version number
        self._zmap_subversion_number = 0  # zmap subversion number
        self._zmap_last_output = ''  # last full ascii zmap output
        is_zmap_found = False  # true if we have found zmap
        self._all_host=None
        self.__process = None
        self._command=None
        # regex used to detect zmap (http or https)
        regex = re.compile(
            'zmap [0-9]*\.[0-9]*\.[0-9].*'
        )
        # launch 'zmap -V', we wait after
        # 'zmap version 5.0 ( http://zmap.org )'
        # This is for Mac OSX. When idle3 is launched from the finder, PATH is not set so zmap was not found
        for zmap_path in zmap_search_path:
            try:
                if sys.platform.startswith('freebsd') \
                        or sys.platform.startswith('linux') \
                        or sys.platform.startswith('darwin'):
                    p = subprocess.Popen([zmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE,
                                         close_fds=True)
                else:
                    p = subprocess.Popen([zmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE)
            except OSError:
                pass
            else:
                self._zmap_path = zmap_path  # save path
                break
        else:
            raise PortScannerError(
                'zmap program was not found in path. PATH is : {0}'.format(
                    os.getenv('PATH')
                )
            )

        self._zmap_last_output = bytes.decode(p.communicate()[0])  # sav stdout
        for line in self._zmap_last_output.split(os.linesep):
            if regex.match(line) is not None:
                is_zmap_found = True
                # Search for version number
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._zmap_version_number = int(line[rv.start():rv.end()])
                    self._zmap_subversion_number = int(
                        line[rsv.start() + 1:rsv.end()]
                    )

                break

        if not is_zmap_found:
            raise PortScannerError('zmap program was not found in path')

        return

    def get_zmap_last_output(self):
        """
        Returns the last text output of zmap in raw text
        this may be used for debugging purpose

        :returns: string containing the last text output of zmap in raw text
        """
        return self._zmap_last_output

    def zmap_version(self):
        """
        returns zmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        :returns: (zmap_version_number, zmap_subversion_number)
        """
        return (self._zmap_version_number, self._zmap_subversion_number)

    def scanbyfile(self,path,ports):
        pass
    def scanbylist(self,lists,ports):
        pass

    def scan(self, hosts='127.0.0.1', ports=None, arguments='', sudo=False):
        """
        Scan given hosts

        May raise PortScannerError exception if zmap output was not xml

        Test existance of the following key to know
        if something went wrong : ['zmap']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as zmap use it 'scanme.zmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: int for ports as zmap use it '22'
        :param arguments: string of arguments for zmap '-q'
        :param sudo: launch zmap with sudo if True

        :returns: scan_result as dictionnary
        """

        # assert os.geteuid() == 0,'zmap should be running with root'
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string  [was {0}]'.format(
                type(hosts))  # noqa
            assert ports and type(ports) == (int),'Wrong type for [ports], should be a int [was {0}]'.format(
                type(ports))  # noqa
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))  # noqa
        else:
            assert type(hosts) in (str), 'Wrong type for [hosts], should be a string  [was {0}]'.format(
                type(hosts))  # noqa
            assert ports and type(ports)==(int), 'Wrong type for [ports], should be a string [was {0}]'.format(
                type(ports))  # noqa
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))  # noqa


        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)
        # Launch scan
        args = [self._zmap_path] + h_args + ['-p', str(ports)] * (ports is not None) + f_args
        if sudo:
            args = ['sudo'] + args
        self._command=args
        p = subprocess.Popen(args, bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # wait until finished
        # get output
        (self._zmap_last_output, zmap_err) = p.communicate()
        self._zmap_last_output = bytes.decode(self._zmap_last_output)
        zmap_err = bytes.decode(zmap_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-zmap mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # zmap.scan() returns nothing. This behavior also diverges significantly
        # from commandline zmap, which simply stderrs individual problems but
        # keeps on trucking.
        zmap_err_keep_trace = []
        zmap_warn_keep_trace = []
        zmap_info_keep_trace=[]
        if len(zmap_err) > 0:
            regex_warning = re.compile('\[WARN\].*', re.IGNORECASE)
            regex_info = re.compile('\[INFO\].*', re.IGNORECASE)
            regex_fatal = re.compile('\[FATAL\].*', re.IGNORECASE)
            for line in zmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    rgi=regex_info.search(line)
                    rgf=regex_fatal.search(line)
                    if rgw is not None:
                        # sys.stderr.write(line+os.linesep)
                        zmap_warn_keep_trace.append(line + os.linesep)
                    elif rgi is not None:
                        zmap_info_keep_trace.append(line + os.linesep)

                    elif rgf is not None:
                        zmap_err_keep_trace.append(line + os.linesep)
                        # raise PortScannerError(zmap_err)
                    else:
                        zmap_info_keep_trace.append(line)




        return self.analyse_zmap_scan(
            zmap_output=self._zmap_last_output,
            zmap_err=zmap_err,
            zmap_err_keep_trace=zmap_err_keep_trace,
            zmap_warn_keep_trace=zmap_warn_keep_trace,
            port=ports

        )

    def analyse_zmap_scan(self,port=None, zmap_output=None, zmap_err='', zmap_err_keep_trace='', zmap_warn_keep_trace=''):
        """
        Analyses zmap  scan ouput

        May raise PortScannerError exception if zmap output was not xml

        Test existance of the following key to know if something went wrong : ['zmap']['scaninfo']['error']
        If not present, everything was ok.

        :param zmap_output:  string to analyse
        :returns: scan_result as dictionnary
        """
        if zmap_output is not None:
            self._zmap_last_output = zmap_output
        scan_result = {}
        scan_result['alive']=[]
        scan_result['error_info']=[]
        scan_result['warn_info']=[]
        if len(self._zmap_last_output)>0:
            scan_result['alive']=self._zmap_last_output.split()
        if zmap_err_keep_trace:
            scan_result['error_info']=zmap_err_keep_trace
        if zmap_warn_keep_trace:
            scan_result['warn_info']=zmap_warn_keep_trace
        # zmap command line
        scan_info={}
        scan_info['scaninfo']={}
        scan_info['scaninfo'][port]=scan_result
        scan_info['command_line']=' '.join(i for i in self._command)
        self._scan_result = scan_info  # store for later use
        return scan_info

    def __getitem__(self,port=None):
        """
        returns a port's detail
        """

        if sys.version_info[0] == 2:
            assert port and type(port) ==int, 'Wrong type for [host], should be a int [was {0}]'.format(
                type(port))
        else:
            assert port and type(port) == int, 'Wrong type for [host], should be a int [was {0}]'.format(type(port))
        return self._scan_result['scaninfo'].get(port,{}).get('alive',None)

    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if self._command:
            if self._all_host:
                return self._all_host
            else:

                args = self._command+['-d']+['-c 0']
                p = subprocess.Popen(args,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE
                                     )

                # wait until finished
                # get output
                (msg, msg_err) = p.communicate()
                if msg:
                    template=re.compile(r"""daddr: ((?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d]))""")
                    hosts=template.findall(msg)
                    self._all_host=hosts
                    return hosts


                else:
                    return []

        else:
            return []


    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'command_line' in self._scan_result, 'Do a scan before trying to get result !'

        return self._scan_result['command_line']

    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        assert 'scaninfo' in self._scan_result, 'Do a scan before trying to get result !'

        return self._scan_result['scaninfo']



    def has_port(self, port):
        """
        returns True if port has result, False otherwise
        """
        assert type(port) is int, 'Wrong type for [host], should be a int [was {0}]'.format(type(port))
        assert 'scaninfo' in self._scan_result, 'Do a scan before trying to get result !'

        if self._scan_result['scaninfo'].get(port,{}).get('alive',None):
            return True

        return False

    def csv(self):
        """
        returns CSV output as text

        Example :
        host;port;status;
        127.0.0.1;port;open

        """
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if sys.version_info < (3, 0):
            fd = io.BytesIO()
        else:
            fd = io.StringIO()

        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = [
            'host',
            'port',
            'state',
        ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    hostname = ''
                    for h in self[host]['hostnames']:
                        hostname = h['name']
                        hostname_type = h['type']
                        csv_row = [
                            host, hostname, hostname_type,
                            proto, port,
                            self[host][proto][port]['name'],
                            self[host][proto][port]['state'],
                            self[host][proto][port]['product'],
                            self[host][proto][port]['extrainfo'],
                            self[host][proto][port]['reason'],
                            self[host][proto][port]['version'],
                            self[host][proto][port]['conf'],
                            self[host][proto][port]['cpe']
                        ]
                        csv_ouput.writerow(csv_row)

        return fd.getvalue()


############################################################################


def __scan_progressive__(self, hosts, ports, arguments, callback, sudo):
    """
    Used by PortScannerAsync for callback
    """
    for host in self._nm.listscan(hosts):
        try:
            scan_data = self._nm.scan(host, ports, arguments, sudo)
        except PortScannerError:
            scan_data = None

        if callback is not None:
            callback(host, scan_data)
    return


############################################################################


class PortScannerAsync(object):
    """
    PortScannerAsync allows to use zmap from python asynchronously
    for each host scanned, callback is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects zmap on the system and zmap version
        * may raise PortScannerError exception if zmap is not found in the path

        """
        self._process = None
        self._nm = PortScanner()
        return

    def __del__(self):
        """
        Cleanup when deleted

        """
        if self._process is not None:
            try:
                if self._process.is_alive():
                    self._process.terminate()
            except AssertionError:
                # Happens on python3.4
                # when using PortScannerAsync twice in a row
                pass

        self._process = None
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None, sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard zmap is catched and you won't know about but get None as scan_data

        :param hosts: string for hosts as zmap use it 'scanme.zmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as zmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for zmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch zmap with sudo if true
        """

        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(
                type(hosts))
            assert type(ports) in (
            str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
                type(ports))
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))

        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(
            str(callback))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nzmap.nm.get_zmap_last_output()'

        self._process = Process(
            target=__scan_progressive__,
            args=(self, hosts, ports, arguments, callback, sudo)
        )
        self._process.daemon = True
        self._process.start()
        return

    def stop(self):
        """
        Stop the current scan process

        """
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout

        :param timeout: default = None, wait timeout seconds

        """
        assert type(timeout) in (
        int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    def still_scanning(self):
        """
        :returns: True if a scan is currently running, False otherwise

        """
        try:
            return self._process.is_alive()
        except:
            return False


############################################################################


class PortScannerYield(PortScannerAsync):
    """
    PortScannerYield allows to use zmap from python with a generator
    for each host scanned, yield is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects zmap on the system and zmap version
        * may raise PortScannerError exception if zmap is not found in the path

        """
        PortScannerAsync.__init__(self)
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard zmap is catched and you won't know about it

        :param hosts: string for hosts as zmap use it 'scanme.zmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as zmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for zmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch zmap with sudo if true

        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nzmap.nm.get_zmap_last_output()'

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo)
            except PortScannerError:
                scan_data = None
            yield (host, scan_data)
        return

    def stop(self):
        pass

    def wait(self, timeout=None):
        pass

    def still_scanning(self):
        pass





class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)



