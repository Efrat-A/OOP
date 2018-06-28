#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import json
import sys
import time

try :
    # from registerSubs import Subscribe
    import psycopg2
except:
    pass

from pycbw.winutils import CreateSession, LocaleWinrm, ExceptionHandler
av_keywords = ["MalwareBytes", "defender", "Virus", "Norton", "PCProtect", "McAfee", "BullGuard", "AVG", "TotalAV",
               "kaspersky"]


def _SecurityLog(cmp, top):
    res = cmp.run_ps('get-Eventlog -newest %d -Logname Security | format-list' % top).std_out.strip()
    print "Security Log wrote to log file \n"
    return res.replace("\r\n", "\n")


def _SystemLog(cmp, top):
    res = cmp.run_ps(
        'get-eventlog system -newest %d | select-object EventID,EntryType ,TimeGenerated,Source,Message,UserName |ConvertTo-Csv -NoTypeInformation' % top).std_out.strip()
    print "System Log wrote to log file \n"
    return res.replace("\r\n", "\n")


def _GetFreeMemory(cmp):
    # Use the class Win32_OperatingSystem and the FreePhysicalMemory property.
    res = cmp.run_ps('gwmi -Class Win32_OperatingSystem | foreach { return $_.FreePhysicalMemory }').std_out.strip()
    return res


def _GetUsers(cmp):
    """
    def _GetUsers(cmp):
        users, users_lst = [], []
        res = cmp.run_ps('gwmi -Query "select * from win32_loggedonuser" | format-list __path').std_out
        try:
            res = res.replace('\r\n         ', '')
            users = parseCmdTable('Domain=\\\\\"(.*?)\\\\\",Name=\\\\\"(.*?)\\\\\".*LogonId=\\\\\"(.*)\\\\\"', res,
                                  '\r\n\r\n')
        except Exception as ex:
            print ex
            pass
        tmp_user = []
        for user in users:
            if tmp_user:
                if tmp_user[0] == user[0] and tmp_user[1] == user[1]:
                    tmp_user[2].append(user[2])
                else:
                    users_lst.append(tmp_user)
                    tmp_user = user
                    tmp_user[2] = tmp_user[2].split()
            else:
                tmp_user = user
                tmp_user[2] = tmp_user[2].split()
        users = []
        for user in users_lst:
            usr = {}
            usr["Domain"] = user[0].strip()
            usr["Username"] = user[1].strip()
            usr["LogonId"] = user[2]
            users.append(usr)
        return json.dumps(users, indent=4)
    """
    #     ps_query= """$startDate = (Get-Date).AddMinutes(-20)
    # $events =
    # $logD = @{}
    #
    # Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startDate}| %%{
    #     #$message = $event.Message
    #     $event=$_
    #     $event.Message -match "Account Name:\s(.*)\n" | foreach {echo $matches;$userName = $matches[1];echo $username  }
    #     echo "11111"
    #
    #     $event.Message -match "Logon ID:\s(.*)\n" | foreach {echo $matches; $logonID = $matches[1];echo $logonID; break  }
    #     echo "2222"
    #     $event.Message -match "Logon Type:\s(.*)\n" | foreach {echo $matches;$type = $matches[1]; echo $type;break  }
    #
    #     $time = $event.TimeCreated.ToString()
    #
    #     $logD += @{ $logonID= @{'userName' = $userName; 'time' =  $time.ToString(); 'logonType' = $type;}}
    #       };
    # foreach ( $k in $logd.keys ){ write-Host $k , ":";
    # foreach ( $sk in $logd[$k] ) { foreach( $msk in $sk.keys) {write-Host $msk, ":", $sk[$msk] } }} """
    ps_query = """$startDate = (Get-Date).AddMinutes(-%s)
$startDate2 = (Get-Date).AddMinutes(-%s)
$start=(get-date)
#$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624 ; StartTime=$startDate} -ErrorAction SilentlyContinue
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624 } -ErrorAction SilentlyContinue
$logD = @{}
foreach ($event in $events)
{
    $userName = $event.Properties[5].value
    $logonID = $event.Properties[7].value
    $type = $event.Properties[8].value
    $time = $event.TimeCreated.ToString()
    if(!$logD.ContainsKey("$logonID"))
    {
        $logD += @{"$logonID" = @{'userName' = $userName; 'time' =  $time.ToString();'logonType' = $type; 'isLogged' = $true}}
    }
}
 $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4634 } -ErrorAction Stop #find logoff events
    foreach ($event in $events)
    {
        $logonID = $event.Properties[3].value
        $toChange = @{}
        foreach($key in $logD.Keys)
        {
            if($key -eq $logonID)
            {
                $toChange += @{$key = $false}
            }
        }
        foreach($key in $toChange.Keys)
        {
            $logD.$key.'isLogged' = $false
        }
    }
    foreach ( $k in $logd.keys )
    {
        Echo $k
        foreach ( $sk in $logd[$k] ) 
        { 
            foreach( $msk in $sk.keys) {write-Host $msk ":" $sk[$msk] } 
        }
    } Echo "-------------LOGON USERS--------------" 
    foreach ($key in $logD.Keys)
    {
        if($logD.$key.'isLogged')
        {
            Write-Host $logD.$key.'userName'
        }
    }Echo "total seconds"
    $end=get-date
     echo $($end-$start).totalseconds""" %(2,1)
    res = cmp.run_ps(ps_query)
    #print res
    print res.status_code
    print res.std_err
    return res.std_out


def _GetFW(cmp):
    if False:
        res = cmp.run_ps('netsh advfirewall show allprofiles').std_out
        try:
            res = res.replace('\r\n         ', '')
            res = res.replace('\r\n', ' ')
            res = res.replace('----------------------------------------------------------------------', '')
            reg = parseCmdTable(
                '(Domain) Profile Settings.*?(State)\s*([A-Z]*).*?(FileName)\s*([^\s]*).*?(Private).*?(State)\s*([^\s]*).*?(FileName)\s*([^\s]*).*?(Public).*?(State)\s*([^\s]*).*?(FileName)\s*([^\s]*).*',
                res, '\n')
            d = reg[0]  # data from res after regex
            dic = {d[0]: {d[1]: d[2], d[3]: d[4]}, d[5]: {d[6]: d[7], d[8]: d[9]}, d[10]: {d[11]: d[12], d[13]: d[14]}}
            return dic
        except Exception as ex:
            print ex
            pass
    output = cmp.run_cmd('netsh advfirewall show currentprofile')
    lines = output.std_out.split('\r\n')
    if len(lines) > 3:
        profile = lines[1].split()[0]
        state = lines[3].split()[-1]
        return "%s = %s" % (profile, state)
    print lines
    return ""


def parseCmdTable(regex, res, chrsplit):
    # gets regex of wanted row and returns the proper result
    total = []
    try:
        res = res.split(chrsplit)
        for i in res:
            a = re.findall(regex, i)
            if len(a) > 1:
                total.append(a[0])
            else:
                total.append(a)
    except:
        print ExceptionHandler(sys.exc_info)
        pass
    return map(lambda x: list(x[0]), filter(lambda x: x != [], total))


def _GetMalwareVisits(domains):
    visited = []
    try:
        conn = psycopg2.connect(database="cbwdb", user="postgres")
        cur = conn.cursor()
        q = "SELECT value FROM policy.domains_malware where    "  # spaces on purpose
        for domain in domains:
            q += "value = '" + ('.' + domain[0])[::-1] + "' or "
        q = q[:-3]
        cur.execute(q)
        for domain in cur.fetchall():
            visited.append(domain)
    except:
        print ExceptionHandler(sys.exc_info)
        pass
    return json.dumps(visited)


def _GetARPRecords(cmp, real):
    attacker_mac = ''
    res = cmp.run_ps("arp -a").std_out
    for i in map(lambda x: list(x), re.findall("\s*([0-9\.]*)\s*([0-9\-a-z]*)\s*([a-z]*)\s*", res)[16:-1]):
        if i[0] == real[0] and i[1] != real[1]:
            print 'spoof found!!!'
            attacker_mac = real[1]
    return attacker_mac


def _GetDNSRecords(cmp):
    # list of: (domain, ip)
    res = cmp.run_cmd("ipconfig /displaydns").std_out
    try:
        res = parseCmdTable(
            "Record\sName\s\.\s\.\s\.\s\.\s\.\s:\s(.*)\n.*\n.*\n.*\n.*\n.*A\s\(Host\)\sRecord\s\.\s\.\s\.\s:\s(.*)",
            res, '\r\n\r\n')
        for i in res:
            i[0] = i[0].strip()
    except Exception as ex:
        print ex
        pass
    return res


# sans ideas : dns recoreds, scripts, event's id, cmd line,reg keys, ns, services.

def _GetAllProc(cmp):
    """
    [   {
            "exec_line":"",
            "path":"",
            "pid":"",
            "ppid":"",
            "sockets":[socket, socket...]
        },
    ]
    """
    procs = []
    res = cmp.run_ps("wmic process get processid,parentprocessid,executablepath,commandline | format-list").std_out
    try:
        ps = parseCmdTable("(.*?)\s{10,}(.*?)\s{10,}([0-9]*)\s{10,}([0-9]*)", res, '\r\n\r\n')[1:]
        sockets = _GetNSInfo(cmp)
        for p in ps:
            p.append([])

        for sock in sockets:
            for p in ps:
                if sock[4] == p[2]:
                    p[4].append(sock)

        for p in ps:
            proc = {}
            proc["exec_line"] = p[0].strip()
            proc["path"] = p[1].strip()
            proc["pid"] = p[2].strip()
            proc["ppid"] = p[3].strip()
            socks = []
            for sock in p[4]:
                curr_sock = {}
                curr_sock["protocol"] = sock[0].strip()
                curr_sock["Local_address"] = sock[1].strip()
                curr_sock["Foreign address"] = sock[2].strip()
                curr_sock["State"] = sock[3].strip()
                socks.append(curr_sock)
            proc["sockets"] = socks
            procs.append(proc)

    except Exception as ex:
        print ex
    return json.dumps(procs)


def _GetNSInfo(cmp):
    sockets = []
    res = cmp.run_ps("netstat -a -n -o").std_out
    try:
        tmp = parseCmdTable("\s{2}([^\s]*)\s{4}([^\s]*)\s{2,}([^\s]*)\s{4,}([^\s]*)\s{4,}([^\s]*)", res, '\r\n')
        sockets = tmp[1:]
        # list of lists : [protocol, local address, foreign address, state, PID]
    except:
        print ExceptionHandler(sys.exc_info)
        pass
    return sockets


def _GetHashes(cmp, date):
    res = cmp.run_ps('forfiles /M *.exe /P C:\\ /S /D +' + date + ' /C "cmd /c echo @path"').std_out
    print res.split('\r\n')

# ----------------------------------------------------------------------------------
def _GetHardware(cmp) :
    system = _GetSystemInfo(cmp)
    processors = _GetProcessorsInfo(cmp)
    adapters = _GetNetworkAdaptersInfo(cmp)
    drives = _GetDiskInfo(cmp)
    baddevices = _GetBadDevice(cmp)
    system['Processors'] = processors

    data = {'System' :system,
            'Network Adapters': adapters,
            'Disk Drives' : drives,
            'Bad Devices' : baddevices
            }
    return json.dumps(data, indent=4, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def _ParseAnswer(result, is_retval_dict):
    out = []
    if result:
        result = result + '\r\n'
        obj = dict()
        i = 0
        for line in result.split('\r\n'):
            if line in [''] and obj:
                if is_retval_dict:
                    return obj
                out.append({i: obj})
                i = i + 1
                obj = dict()

            else:
                key = line.split(':')[-0].strip()
                val = line.split(':', 1)[-1].strip()
                if key != val:
                    obj[key] = val
    if is_retval_dict:
        return dict()
    return out

def _GetSystemInfo(cmp):
    #Use the Win32_ComputerSystem class and check the value of the TotalPhysicalMemory property.
    res = cmp.run_ps('Get-WmiObject -Class Win32_ComputerSystem | format-list Manufacturer, Model, Name, TotalPhysicalMemory').std_out.strip()
    return _ParseAnswer(res, True)
def _GetProcessorsInfo(cmp):
    res = cmp.run_ps('Get-WmiObject -Class Win32_Processor | format-list Name, NumberOfCores,'+
                    ' NumberOfLogicalProcessors, Manufacturer, Family, Architecture').std_out.strip()
    return _ParseAnswer(res, False)  #False - returning a list of processors
def _GetNetworkAdaptersInfo(cmp):
    q = """Get-WmiObject Win32_NetworkAdapter |% { if($_.NetEnabled -eq $True) { $index = $_.index
 $ip=$(Get-WmiObject Win32_NetworkAdapterConfiguration|%{ if($_.Index -eq $index) {return $_.IPAddress}})
 $person = new-object PSObject
 $person | add-member -type NoteProperty -Name Name -Value $_.Name
 $person | add-member -type NoteProperty -Name IPv4 -Value $ip[0]
 $person | add-member -type NoteProperty -Name IPv6 -Value $ip[1]
  $person | add-member -type NoteProperty -Name MacAddress -Value $_.MacAddress
  $person | add-member -type NoteProperty -Name AdapterType -Value $_.AdapterType
  $person | add-member -type NoteProperty -Name Manufacturer -Value $_.Manufacturer
 return $person;}}"""
    r = cmp.run_ps(q.replace('\n', ';')) #command is more than one line
    res = r.std_out.strip()
    return _ParseAnswer(res, False)  #returns list of Adapters

def _GetDiskInfo(cmp):
    res = cmp.run_ps('Get-WmiObject win32_DiskDrive | format-list Name, Manufacturer, Model, Partitions, Size ').std_out.strip()
    return _ParseAnswer(res, False)  # returns list of drive information


def _GetBadDevice(cmp):
    #Use the Win32_PnPEntity class and use the following clause in your WQL query. WHERE ConfigManagerErrorCode <> 0 Note that this code may not detect USB devices that are missing drivers.
    res = cmp.run_ps('Get-WmiObject Win32_PNPEntity | where {$_.ConfigManagerErrorcode -ne 0} | format-list Name,'+
            ' Classguid, Description, DeviceID, Manufacturer, PNPDeviceID, Service').std_out.strip()
    return _ParseAnswer(res, False)  # returns list of Bad devices

# ----------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------



def _GetPsReq (cmp, verbose) :
    res = cmp.run_ps("Get-WinEvent -FilterHashTable @{LogName='Windows PowerShell'; ID=400} | % {Echo $_.Message; echo '@'}")
    # print res.std_err
    events = res.std_out.split('@')

    regex_enc = re.compile("-encodedcommand\s(.*)\r\n", re.IGNORECASE)
    regex_smp =re.compile("-command\s(.*)\r\n", re.IGNORECASE)
    regex_other = re.compile("HostApplication=(.*)\r\n")
    stats = {'bg_encoded': 0 ,'bg_command':[] ,'manual':[] }
    for i,e in enumerate(events):
        if e.strip() and i > 1 and ( verbose or i < 20 ):
            try:
                enc = re.findall(regex_enc, e)
                if not enc:
                    simp = re.findall(regex_smp, e)
                    if not simp:
                        other = re.findall(regex_other, e)
                        stats['manual'].append(i)
                        print '\033[96m', i, ': ', '< manual access >', other[0] ,'\033[0m'
                    else:
                        stats['bg_command'].append(i)
                        print '\033[91m', i, ': ', simp[0] ,'\033[0m'
                else:
                    stats['bg_encoded'] += 1
                    print '\033[93m', i, ': ', base64.b64decode(enc[0]).replace('\x00', '') , '\033[0m'

            except Exception as ex:
                print '-' * 10, str(ex), '-' * 10
                print e
                print "-" * 50
                pass

    return {'events':len(events), 'detailed': stats}



# ----------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------
def _GetSubscription(cmp, identifier):
    binder = _GetBinders(cmp)
    cons = _GetConsumers(cmp)
    fil = _GetFilters(cmp)

    print identifier, ": binders, consumers and filters wrote to log file \n"
    return 'binders:\n\n%s\n\nconsumers:\n\n%s\n\nfilters:\n\n%s\n\n' % (
        '\n'.join(binder), '\n'.join(cons), '\n'.join(fil))


def _GetFilters(cmp):
    fil = cmp.run_ps('gwmi -Namespace "root/subscription" -Class __EventFilter|%{ return $_.Name}').std_out.strip()
    return list(fil.split('\r\n')) if fil else []


def _GetConsumers(cmp):
    fil = cmp.run_ps('gwmi -Namespace "root/subscription" -Class __EventConsumer|%{ return $_.Name}').std_out.strip()
    return list(fil.split('\r\n')) if fil else []


def _GetBinders(cmp):
    fil = cmp.run_ps(
        'gwmi -Namespace "root/subscription" -Class __FiltertoConsumerBinding|%{return $_.Filter.split("`"")[1] }').std_out.strip()
    return list(fil.split('\r\n')) if fil else []


# -------------------------------------------------
def _RemoveFilter(cmp, filtername):
    r = cmp.run_ps(
        'Get-WMIObject -Namespace root\Subscription -Class __EventFilter|?{ $_.Name -eq "%s"} | Remove-WmiObject' % (
            filtername))
    return r.status_code


def _RemoveConsumer(cmp, consName):
    r = cmp.run_ps(
        'Get-WMIObject -Namespace root\Subscription -Class __EventConsumer |?{$_.Name -eq "%s"}| Remove-WmiObject' % (
            consName))
    return r.status_code


def _RemoveBinding(cmp, filtername):
    r = cmp.run_ps(
        'Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE `"%' + filtername + '%`"" | Remove-WmiObject')
    return r.status_code


def _RemoveSubs(cmp, identifier, filters, verbose):
    try:
        # print filters
        hostfil = set(_GetFilters(cmp))
        hostcon = set(_GetConsumers(cmp))
        hostbin = set(_GetBinders(cmp))
        hostfil = hostfil.union(hostcon)
        hostfil = hostfil.union(hostbin)

        rm = []
        for fil in hostfil:
            if (fil in filters):
                fil = fil.strip()
                a = _RemoveFilter(cmp, fil)
                b = _RemoveConsumer(cmp, fil)
                c = _RemoveBinding(cmp, fil)
                if (a == 0 and b == 0 and c == 0):
                    rm.append(fil)
                    if verbose:
                        print identifier, ': removed ', fil
        if rm:
            return "removed : %s" % ('\n'.join(rm))
        else:
            return "nothing to do"
    except Exception, e:
        print "%s [ %s ] %s " % (sys.exc_info()[2], type(e), e)
        return "failed"


def _ActivateLogging(computer, addr):
    r = computer.run_cmd('auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable')
    # color errors
    print "Activate Logging [%s]: %s \033[91m %s \033[0m" % (addr, r.std_out.strip(), r.std_err.strip())


# ----------------------------------------------------------------------------------
# filtersListFile is the path of filters list
def _GetFiltersFromDB(filtersListFile, remove):
    try:
        conn = psycopg2.connect(database="cbwdb", user="postgres")
        cur = conn.cursor()
        if filtersListFile:
            with open(filtersListFile, 'r') as f:
                filters = f.readlines()
            filters = "(" + str(map(lambda x: x.strip(), filters))[1:-1] + ")"
            cur.execute(
                "SELECT name, query, namespace, language FROM policy.wmi_filters WHERE active and name in " + filters)
        elif remove:
            cur.execute("SELECT name, query, namespace, language FROM policy.wmi_filters ")
        else:
            cur.execute("SELECT name, query, namespace, language FROM policy.wmi_filters WHERE active")

        filterRes = []
        for name, query, namespace, language in cur.fetchall():
            # print name, query, classs, namespace, language
            obj = [name, query, namespace, language]
            filterRes.append(obj)

        conn.close()

        return filterRes

    except Exception, e:
        print "failed accsses to DB " + str(type(e)) + ", " + str(e)


def _GetAuthFromDB():
    obj = {}
    try:
        conn = psycopg2.connect(database="cbwdb", user="postgres")
        cur = conn.cursor()
        cur.execute(
            "SELECT name, usr, passwd, t.ip from policy.win_domains, configuration.interfaces as t where t.service='MGMT'")
        for name, usr, passwd, srv in cur.fetchall():
            obj = {"user": usr, "domain": name, "password": passwd, "read_timeout": 30, "operation_timeout": 20, "srv": srv}
            break
        conn.close()
    except:
        print ExceptionHandler(sys.exc_info)
        pass
    return obj


def _GetHostsFromDB():
    hosts = []
    try :
        conn = psycopg2.connect(database="cbwdb", user="postgres")
        cur = conn.cursor()
        cur.execute("SELECT address from policy.win_hosts")
        for address in cur.fetchall():
            hosts.append(str(address[0]))
        conn.close()
    except:
        print ExceptionHandler(sys.exc_info)
        pass
    return hosts

import re




def test_my_mac(addr, comp):
    data = _GetNetworkAdaptersInfo(comp)
    for idx in data:  # list of dict
        for i, adapter in idx.items():
            if addr == adapter['IPv4']:
                return adapter['MacAddress']
    return ''


# ----------------------------------------------------------------------------------
def _GetPSVersion(computer):
    psv = computer.run_ps('$PSVersionTable.PSVersion.major').std_out
    n = re.sub(r'[^\x00-\x7f]', '', psv.replace('\r', '').replace('\n', ''))
    if n: return int(n)
    return ''

# ----------------------------------------------------------------------------------
def _GetArch(computer):
    #r = computer.run_ps('(Get-WmiObject Win32_Processor -namespace root/cimv2).addressWidth')
    #r = computer.run_ps('(gwmi Win32_Processor -namespace root/cimv2)[0].AddressWidth') #good for 17.3
    r = computer.run_ps('gwmi Win32_Processor -namespace root/cimv2|%{ return $_.AddressWidth}')
    arch = r.std_out.strip()
    print 'ARCH -out:', repr(r.std_out)
    print 'ARCH -err:', repr(r.std_err)
    n = arch.split('\r\n')[0]
	#.split(':')[1].lstrip()
    print '\n\n', n, '\n'
    return n
    


# ----------------------------------------------------------------------------------
def _GetData(computer):
    data = {'os': str(computer.run_ps('(gwmi win32_operatingsystem -namespace root/cimv2).caption').std_out).strip(),
            'psv': _GetPSVersion(computer),
            'vm': _IsVirtual(computer),
            'arch': _GetArch(computer),
            'wfilters': _GetWmiFilters(computer),
            'firewall': _GetFirewallState(computer),
            'activefirewall': _GetFirewallRunning(computer),
            'winupdate': _GetWindowsUpdate(computer),
            'failedlogonscount': _FailLogonCount(computer)
            }
    res = _GetAV(computer)
    if not res:
        res = _GetAV_Servers(computer)
    data['protection'] = res
    acdc_tuple = _GetScreenLock(computer)
    if acdc_tuple:
        data['scrlock'] = {'ac': acdc_tuple[0], 'dc': acdc_tuple[1]}
    if "Microsoft Windows 10" in data['os']:
        data['version'] = str(computer.run_ps(
            '(Get-ItemProperty -Path \\"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\\" -Name ReleaseId).ReleaseId').std_out).strip()
    if ("Microsoft Windows 8.1 Pro" in data['os']) or ("Windows 7" in data['os']):
        data['version'] = data['arch']
    return json.dumps(data, separators=(',', ':'), ensure_ascii=False)


# ----------------------------------------------------------------------------------
def _IsVirtual(computer):
    ans = computer.run_ps('(gwmi -class win32_computersystem).model').std_out
    if 'Virtual' in ans:
        return 'True'
    return 'False'


# ----------------------------------------------------------------------------------
def _GetWmiFilters(cmp):
    fil = cmp.run_ps('gwmi -Namespace root/subscription -Class __EventFilter|foreach{return $_.name}').std_out
    fil = re.sub(r'[^\x00-\x7f]', '', fil).strip()
    return list(fil.split('\r\n')) if fil else []


# ----------------------------------------------------------------------------------
def _GetAV(cmp):
    total = []
    res = cmp.run_ps(
        'Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct| format-list displayname,pathtosignedproductexe,productstate').std_out
    names = re.findall("displayname\s*:([^\r\n]*)", res)
    paths = re.findall("pathtosignedproductexe\s*:([^\r\n]*[\r\n]*)[\s]*(.*[\r\n]*)productstate", res)
    paths = map(lambda x: (x[0] + x[1]).replace('\r\n', ''), paths)
    statuses = re.findall("productstate\s*:([^\r\n]*)", res)
    
    for av in xrange(len(names)):
        new_av = {}
        up_or_down = "down"
        up_to_date = "outdated"
        if hex(int(statuses[av]))[3:5] in ("10", "11"):
            up_or_down = "up"
        if hex(int(statuses[av]))[5:7] == "00":
            up_to_date = "up-to-date"
        new_av["name"] = names[av].strip()
        new_av["path"] = paths[av]
        new_av["db_status"] = up_to_date
        new_av["status"] = up_or_down
        total.append(new_av)
    return total


# ----------------------------------------------------------------------------------

def _GetAV_Servers(cmp):
    keywords = ', '.join(map(repr, av_keywords))
    netstring = """$data = @{}
$keyWords = @(%s)
$a = Get-ChildItem -path $env:ProgramFiles
$dirs = @()
foreach($i in $a){$dirs += $i.FullName}
$a = Get-ChildItem -path ${env:ProgramFiles(x86)}
foreach($i in $a){$dirs += $i.FullName}
foreach($avName in $keyWords){$res = ($dirs -like \\"*$avName*\\")
if($res){$res = $res[0]
if($data.ContainsKey($res)){continue}
$data += @{$res = @{}}
$exePath = @()
$e = Get-ChildItem -Recurse -path $res
foreach($i in $e) { if($i.Extension -eq \\".exe\\") { $exePath += $i.Name } }
foreach($exe in $exePath){
$name = $exe.Substring(0, $exe.Length - 4)
$res2 = Get-Process -Name $name -ErrorAction silentlycontinue
if($res2 -eq $null) { $res2 = Get-Service -Name $name -ErrorAction silentlycontinue}
if($data.Item($res).ContainsKey($name)){continue}
if($res2){if($res2.Status -ne $null){ 
if($res2.Status -eq \\"Stopped\\"){$data.Item($res) += @{$name = 'off'}}else{$data.Item($res) += @{$name = 'on'}
}}else{$data.Item($res) += @{$name = 'on'
}}}else{$data.Item($res) += @{$name = 'off'
}}}}}foreach($k in $data.Keys){Echo ($k+'@')
foreach($j in $data.$k.Keys){Echo ($j+'@@')
Echo $data.$k.$j}}""" % keywords
    res = cmp.run_ps(netstring.replace('\n', ';'))
    msg = res.std_out
    if res.status_code != 0 or not msg:
        return []
    data = {}
    currKey = ''
    currSub = ''
    for line in msg.split('\n'):
        line = line[0:-1]
        if not line:
            continue
        elif line.count('@') == 1:
            currKey = line[0:-1]
            data[currKey] = {}
        elif line.count('@') == 2:
            currSub = line[0:-2]
            data[currKey][currSub] = ''
        elif line.count('@') == 0:
            data[currKey][currSub] = line
    data = avServerParse(data)
    return data


def avServerParse(d):
    ret = []
    db_st = "n/a"
    for path in d:
        for state in d[path]:
            if d[path][state] == "on":
                ret.append({'status': 'up', 'path': path, 'name': path.split('\\')[-1], 'db_status': db_st})
                break
    if len(ret) != len(d.keys()):
        retPaths = [x['path'] for x in ret]
        for path in d:
            if not path in retPaths:
                ret.append({'status': 'down', 'path': path, 'name': path.split('\\')[-1], 'db_status': db_st})
    return ret


# ----------------------------------------------------------------------------------
def _GetFirewallRunning(cmp):
    d = {'profile': 'n/a'}
    output = cmp.run_cmd('netsh advfirewall show currentprofile')
    lines = output.std_out.split('\r\n')
    if len(lines) > 3:
        try:
            d['profile'] = lines[1].split(':')[0].strip()
            d['state'] = lines[3].split()[-1]
        except:
            pass
    return d


# ----------------------------------------------------------------------------------
def _GetFirewallState(cmp):
    r = cmp.run_cmd("netsh advfirewall show all state")
    d = {}
    key = None
    for i in r.std_out.split('\r\n'):
        if ':' in i:
            key = i.split(':')[0].strip()
        if '     ' in i and key:
            d[key] = i.split(' ')[-1]
            key = None
    return d


# ----------------------------------------------------------------------------------
def _GetWindowsUpdate(cmp):
    ps_query = 'get-wmiobject -class win32_service| foreach { if($_.name -eq \\"wuauserv\\" -and $_.displayname -eq \\"Windows Update\\"){'
    ps_query += 'return $_.Status, $_.State, $_.StartMode }}'
    r = cmp.run_ps(ps_query)
    r_list = r.std_out.split("\r\n")
    d = {}
    try:
        d['status'] = r_list[0]
        d['state'] = r_list[1]
        d['start_mode'] = r_list[2]  # doest updates downloaded (auto-without premission)
    except:
        d = {'status': 'n/a'}
    return d


# ----------------------------------------------------------------------------------
def _GetName(computer):
    ans = computer.run_ps('(gwmi -class win32_computersystem).name').std_out
    ans = re.sub(r'[^\x00-\x7f]', '', ans.replace('\r', '').replace('\n', ''))
    return ans


def _GetScreenLock(cmp):
    netstring = "powercfg.exe /Q SCHEME_CURRENT SUB_VIDEO"
    res = cmp.run_cmd(netstring)
    msg = res.std_out
    blocks = []
    curr = ''
    for line in msg.split('\r\n'):
        if line:
            curr += line
        else:
            blocks.append(curr)
            curr = ''
    msg = filter(lambda x: "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" in x, blocks)
    if msg:
        msg = msg[0].replace('    ', '\n')
        settings = re.findall(": (0x.*)", msg)
        if settings:
            ac = settings[-2]
            dc = settings[-1]
            if dc and ac:
                return int(ac, 16), int(dc, 16)
    return None


def _FailLogonCount(cmp):
    ps_query = """$startDate=(Get-Date).date.TimeOfDay
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625;StartTime=$startDate;} -ErrorAction SilentlyContinue 
$events.count """
    res = cmp.run_ps(ps_query.replace('\n', ';'))
    counter = re.sub(r'[^\x00-\x7f]', '', res.std_out.replace('\r', '').replace('\n', ''))
    if counter:
        return int(counter)
    return 0

def _Minimal(session, addr):
    ka="taskkill /im \"powershell.exe\" /F"    
    r = session.run_cmd(ka)
    print r.std_out
    ka="taskkill /im \"winrshost.exe\" /F"    
    r = session.run_cmd(ka)
    print r.std_out
    return {}
    name = ''
    cmp = LocaleWinrm(session)
    name = _GetName(cmp)
    data = _GetData(cmp)

    newmac = test_my_mac(addr, cmp)
    mac = newmac

    print repr(data)
    return {'mac': mac, 'name': name }#, 'data': data}



# ----------------------------------------------------------------------------------
if __name__ == "__main__":
    try:
        filters = ["cbw_ShadowCopyCreation",
                   "cbw_VolumeChange", "cbw_DriverCreation", "cbw_Loggon",
                   "cbw_ScheduledJobCreation", "cbw_ShareCreation",
                   "cbw_StartupCommandCreation", "cbw_WmiFilterCreation", "cbw_IP_AddressChange",
                   "cbw_UFD_Plug", "cbw_UFD_Unplug"]

        parser = argparse.ArgumentParser(description='Wmi Report system')
        parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False,
                            help="print status messeges")
        parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", default=False,
                            help="don't print status messages to stdout")
        parser.add_argument("-f", "--file", metavar="PATH", dest="filename", default="log",
                            help="write report to FILE, default is log_address.log")
        parser.add_argument("-o", "--hosts", metavar="FILE", dest="hostsfile", help="hosts file")
        parser.add_argument("-a", "--auth", metavar="FILE", dest="authfile", help="authentication details file")
        parser.add_argument("-p", "--reg", action="store_true", dest="reg", default=False, help="register subscription")
        parser.add_argument("-s", "--subs", action="store_true", dest="subs", default=False,
                            help="add all filters, consumers and binders to output file")
        parser.add_argument("-r", "--rsubs", action="store_true", dest="rsubs", default=False,
                            help="remove all filters, consumers and binders")
        parser.add_argument("-F", "--filters", dest="filters", metavar="FILE",
                            help="filters file to register or remove")
        parser.add_argument("-w", "--firewall", action="store_true", dest="firewall", default=False,
                            help="add all firewall rules to output file")
        parser.add_argument("-l", "--getlog", action="store_true", dest="log", default=False,
                            help="add security and system log to output file")
        parser.add_argument("-e", "--eventLog", metavar="N", type=int, default=10, dest="eventlimit",
                            help="EventLog newest N events default=10")
        parser.add_argument("-H", "--hardware", action="store_true", dest="hardware", default=False,
                            help="add hardware info to output file")
        parser.add_argument("-i", "--software", action="store_true", dest="software", default=False,
                            help="add software info to output file")
        parser.add_argument("-d", "--domains", action="store_true", dest="domains", default=False,
                            help="check malware domains")
        parser.add_argument("-u", "--users", action="store_true", dest="users", default=False,
                            help="get system's users")
        parser.add_argument("-P", "--procs", action="store_true", dest="procs", default=False,
                            help="get all system's processes")
        parser.add_argument("-A", "--arp", action="store_true", dest="arp", default=False, help="get arp records")
        parser.add_argument("-b", "--av", action="store_true", dest="avs", default=False,
                            help="get all system's antiviruses")
        parser.add_argument('-c', '--list', dest="host_list", nargs='+', help='list of hosts', default=False)
        parser.add_argument("--audit", action="store_true", dest="auditlogs", default=False,
                            help="activate network log")
        parser.add_argument("--get-ps-requests", action="store_true", dest="get_ps_requests", default=False,
                            help="list out translated powershell requests as runned on the client")

        args = parser.parse_args()
        verbose = args.verbose

        if args.authfile:
            f_conf = open(str(args.authfile), "r")
            conf = f_conf.read()
            try:
                conf_json = json.loads(conf)
            except Exception:
                print "authentication file is not json, taking from db"
                conf_json = _GetAuthFromDB()
                pass
        else:
            conf_json = _GetAuthFromDB()

        hosts_additional_arg = []
        hosts = []
        if args.host_list:
            hosts_additional_arg = args.host_list

        if args.hostsfile:
            with open(str(args.hostsfile), "r") as f_hosts:
                hosts = f_hosts.readlines()

        if not hosts and not hosts_additional_arg:
            hosts = _GetHostsFromDB()

        if (args.filters):
            f_filters = open(str(args.filters), "r")
            filters = f_filters.readlines()
            f_filters.close()
            filters = map(str.strip, filters)

        filtersDB = _GetFiltersFromDB(args.filters, args.rsubs)
        if verbose:
            print json.dumps(conf_json, indent=4, ensure_ascii=False)

        for host in (hosts + hosts_additional_arg):
            try:
                host = host.strip()

                if host != "" and host[0] != "#":

                    print 'connection to : %s' % host

                    log_path = "%s_%s" % (args.filename, host)
                    #f = open(log_path, 'w')

                    # GetHostInfo(host, 'mac',  conf_json['user'], conf_json['domain'], conf_json['password'], 123)

                    cmp = CreateSession(host, conf_json['user'], conf_json['domain'], conf_json['password'])
                    d={}
                    try:
                        d =_Minimal(cmp, host)
                    except:
                        print '[',host,'] failed connect'
                        pass
                    
		    d['log_path'] = log_path
                    print host, json.dumps(d, indent=4, ensure_ascii=False)  # not visible in host log file
                    continue
                    if args.domains:
                       res = _GetMalwareVisits(_GetDNSRecords(cmp))
                       if verbose:
                           print "*--* Checking malware domains *--*"
                           print res
                           print

                       f.write("\n\n---------- Checking malware domains ----------\n\n")
                       f.writelines(res + '\n\n')

                    if args.users:
                       if verbose:
                           print "*--* Grabbing users *--*"
                       res = _GetUsers(cmp)
                       print res
                       if verbose:
                           f.write("\n\n---------- Grabbing users ----------\n\n")
                           f.writelines(res + '\n\n')

                    if args.avs:
                       res = _GetAV(cmp)
                       if verbose:
                           print "*--* Grabbing antiviruses *--*"
                           print res
                           print

                       f.write("\n\n---------- Grabbing antiviruses ----------\n\n")
                       f.writelines(res + '\n\n')

                    if args.arp:
                       res = _GetARPRecords(cmp)
                       if verbose:
                           print "*--* Grabbing arp records *--*"
                           print res
                           print

                       f.write("\n\n---------- Grabbing arp records ----------\n\n")
                       f.writelines(res + '\n\n')

                    if args.procs:
                       res = _GetAllProc(cmp)
                       if verbose:
                           print "*--* Grabbing system's processes *--*"
                           print res
                           print

                       f.write("\n\n---------- Grabbing system's processes ----------\n\n")
                       f.writelines(res + '\n\n')

                    if args.reg:
                       if verbose:
                           print "*--* Register Subscriptions *--*"
                           f.write("\n\n---------- Register Subscriptions ----------\n\n")
                       if filters:
                           Subscribe(cmp, conf_json['srv'], filters)
                           f.writelines(line + u'\n' for line in filters)
                       else:
                           Subscribe(cmp, conf_json['srv'], filtersDB)
                           f.writelines(line + u'\n' for line in filtersDB)

                    # if args.rsubs:
                    #    if filters:
                    #        res = _RemoveSubs(cmp, host, filters, verbose)
                    #    else:
                    #        res = _RemoveSubs(cmp, host, filtersDB, verbose)
                    #    if not res and args.verbose:
                    #        print "*--* Remove Subscriptions *--*"
                    #    if res and args.verbose:
                    #        print "*--* Remove Subscriptions *--*"
                    #        print res
                    #        print
                    #
                    #    f.write("\n\n-------- Remove Subscriptions --------\n\n")
                    #    f.write(res)

                    # if (args.subs or args.reg or args.rsubs):
                    #    res = _GetSubscription(cmp, host)
                    #
                    #    if verbose:
                    #        print "*--* Get Subscriptions *--*"
                    #        print res
                    #        print
                    #
                    #    f.write("\n\n----------- Get Subscriptions -----------\n\n")
                    #    f.write(res)
                    #    f.write("\n")

                    if args.firewall:
                      res = _GetFW(cmp)

                      if verbose:
                          print "*--* Firewall Rules *--*"
                          print res
                          print

                      f.write("\n\n------------ Firewall Rules ------------\n\n")
                      f.write(res)
                      f.write("\n")

                    if args.log:
                       res = _SystemLog(cmp, args.eventlimit)

                       if verbose:
                           print "*--* System Log ( newest %d ) *--*" % args.eventlimit
                           print res
                           print

                       f.write("\n\n---------- System Log ( newest %d ) ---------- \n\n" % args.eventlimit)
                       f.write(res)
                       f.write("\n")

                    if args.hardware:
                       res = _GetHardware(m)
                       if verbose:
                           print "*--* Hardware Info cmp style *--*"
                           print res
                           print
                       f.write("\n\n------------- Hardware Info ------------- \n\n")
                       f.write(res)


                    if args.get_ps_requests :
                        ans = _GetPsReq(cmp, verbose, )
                        print ans
		  

                  # if args.software:
                  #     res = _GetInstalled(cmp)
                  #     if verbose:
                  #         print "*--* Software Info *--*"
                  #         print res
                  #         print

                  #     f.write("\n\n------------- Software Info ------------- \n\n")
                  #     # f.writelines(line + u'\n' for line in res)
                  #     f.write(res)

                    if args.auditlogs:
                       _ActivateLogging(cmp, host)

                    f.close()

            except Exception, e:
                print 'Host Error:', e, type(e)
                print ExceptionHandler(sys.exc_info)
                with open(str(args.filename + '_ERR_' + host), 'w') as e_f:
                    e_f.write("[ %s ] %s " % (type(e), e))
                pass
    except Exception, e:
        print ExceptionHandler(sys.exc_info)

    finally:
        exit()
