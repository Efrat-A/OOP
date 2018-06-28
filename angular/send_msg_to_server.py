"""
Test Tool to check connection

insert authentication details,
ip address of the server holding wmihandler.php file, running apache
and the ip address of windows machine

"""
import time
import winrm
import json

#Insert wanted details
user='administrator@rndvmnet.com' #'wmi@protalix.lan'
pas= 'RnDadmin2015' #'$Mvx2016@'
win_ip='192.168.17.218' #'192.168.17.149'
server_ip='192.168.17.150' #'192.168.16.201'


cmp=winrm.Session(win_ip,auth=(user,pas),transport='ntlm')

tmp1 ="""[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$URI1="https://%s/wmihandler.php"
$request = [System.Net.WebRequest]::Create($URI1);
$request.Method = "POST"
$Body='{"ts":"'+ (get-date).tofiletimeutc()+ '","ip":"%s","name":"'+(hostname).tostring()+'",'
$Body+='"event":{"Title":"hash","pid":'+$pid +',"status":"test" }}'
$encoding = New-Object System.Text.ASCIIEncoding;$bytes = $encoding.GetBytes($Body);
$request.Upload;$requestStream = $request.GetRequestStream();
$requestStream.Write($bytes, 0, $bytes.length)
$requestStream.Close();$response=$request.getResponse();
$reqstream = $response.GetResponseStream()
$sr = new-object System.IO.StreamReader $reqstream;
$result = $sr.ReadToEnd();
write-host $result;
"""% (server_ip, win_ip)
# upload file, test fhandler and wmihandler
tmp_testfile="""$func="`$filepath=`"`$HOME\hashfile.txt`";
`$URI1=`"https://%s/wmihandler.php`";
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
`$request = [System.Net.WebRequest]::Create(`$URI1);`$request.Method = `"POST`"
`$Body='{`"ts`":`"'+ (get-date).tofiletimeutc()+ '`",`"ip`":`"%s`",`"name`":`"'+(hostname).tostring()+'`",'
`$Body+='`"event`":{`"Title`":`"hash`",`"pid`":'+`$pid +',`"path`":`"'+ `$filepath +'`",`"status`":`"start`" }}'
`$encoding = New-Object System.Text.ASCIIEncoding;`$bytes = `$encoding.GetBytes(`$Body);
`$request.Upload;`$requestStream = `$request.GetRequestStream();`$requestStream.Write(`$bytes, 0, `$bytes.length)
`$requestStream.Close();`$response=`$request.getResponse();`$reqstream = `$response.GetResponseStream()
`$sr = new-object System.IO.StreamReader `$reqstream;
`$result = `$sr.ReadToEnd();write-host `$result
`$algs=[Security.Cryptography.HashAlgorithm]::Create(`"%s`");
cd \\
if(!(Test-path `$filepath)){new-item `$filepath -type file -force}
echo `"Test file... `" > `$filepath
`$wc = new-object System.Net.WebClient
`$result = `$false
`$ErrorActionPreference = `"SilentlyContinue`"
`$finish=(get-date).tofiletimeutc()
`$a=`$wc.UploadFile(`"https://%s/fhandler.php?fin=1&host=%s&stime=%s&etime=`$finish`", `$filepath)

"
$msg=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($func))
Invoke-WmiMethod -path win32_process -name create -argumentlist "powershell.exe -windowstyle hidden -executionPolicy Bypass -encodedCommand $msg"
""" %(server_ip, win_ip, "SHA1", server_ip, win_ip, time.time())
tmp = """
$instanceFilter = ([wmiclass]"\\\\.\\root\subscription:__EventFilter").CreateInstance()
$instanceFilter.QueryLanguage = '%s'
$instanceFilter.Query ="%s"
$instanceFilter.Name = '%s'
$instanceFilter.EventNamespace = '%s'
$result = $instanceFilter.Put()
$filterPath = $result.Path
$ListeningPostIP = '%s'
$myip='%s'
$date2=(get-date).ToUniversalTime()
$date=(New-TimeSpan -Start '01/01/1970' -End $date2).TotalSeconds
$script = @"
On Error Resume Next
Dim errString
Dim outputString
Set dateTime = CreateObject("WbemScripting.SWbemDateTime")
dateTime.SetVarDate (now())
outputString = "{""subts"":""$($date)"","
outputString = outputString & "\""ts"":""\" & TargetEvent.Time_Created & "\"","
outputString = outputString & "\""ip"":""$($myip)"","
outputString = outputString & "\""name"":""$($env:COMPUTERNAME)"","
outputString = outputString & "\""event"":{"
outputString = outputString & "\""InstanceClass"":"\"" & TargetEvent.TargetInstance.Path_.Class & "\"","
For Each oProp in TargetEvent.TargetInstance.Properties_
outputString = outputString & ""\"" & oProp.Name & "\"":"\""  & replace(oProp,""\"","") & "\"","
Next
outputString = outputString & "\""subscription"":\""%s\"","
outputString = outputString & "\""EventClass"":""\" & TargetEvent.Path_.Class                                                                                                |
gscript = "`$hash = (Get-FileHash `$args[0] -Algorithm MD5).hash;"
gscript = gscript & "`$outStr = `$args[1] + 'hash:' + `$hash + '}}';"
gscript = gscript & "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}"
gscript = gscript & "Invoke-WebRequest -UseBasicParsing 'https://$($ListeningPostIP)/wmihandler.php' -ContentType 'application/json' -Method POST -Body `$outStr"
strCMD = "powershell -command " & Chr(34) & "&{" & gscript & "}" & Chr(34) & " " & Chr(39) & TargetEvent.TargetInstance.ExecutablePath & Chr(39) & " " & Chr(39) & outputString & Chr(39)
Dim objShell
Set objShell=CreateObject("WScript.Shell")
objShell.Run strCMD, 0
"@
$instanceConsumer = ([wmiclass]"\\\\.\\root\subscription:ActiveScriptEventConsumer").CreateInstance()
$instanceConsumer.Name = '%s'
$instanceConsumer.ScriptingEngine = 'VBScript'
$instanceConsumer.ScriptFilename = ''
$instanceConsumer.ScriptText = $script
$result = $instanceConsumer.Put()
$consumerPath = $result.Path
$instanceBinding = ([wmiclass]"\\\\.\\root\subscription:__FilterToConsumerBinding").CreateInstance()
$instanceBinding.Filter = $filterPath
$instanceBinding.Consumer = $consumerPath
$instanceBinding.Put()
""" %( #self.language, self.query, self.name, self.namespace, server, ip, self.name, self.name
                'WQL','SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA ''Win32_Process''','cbw_ProcessCreation',
                'root/cimv2', server_ip, win_ip,'cbw_ProcessCreation','cbw_ProcessCreation'
                )
tmp2="get-content $HOME\hashfile.txt; remove-item -path $HOME\hashfile.txt"
r=cmp.run_ps(tmp_testfile)
#s=cmp.run_ps(tmp2)
print r.status_code
print r.std_out
print r.std_err
#print s.std_out


#   watch error_log /var/log/httpd/*log
#   check systemctl status httpd
#   check apachectl 



