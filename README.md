# One_Liners
Single line commands for a variety of shell environments.  I got tired of forgetting them so here they are for all to see.

## PowerShell
1. List Windows Event Logs with data:  `Get-WinEvent -ListLog * | ? {$_.RecordCount -gt 0}`
2. Write to file: `Write-Output "foo" | Out-File C:\path\to\file`
3. Display command output to console and append to file: `Get-SomeCommand | Tee-Object -FilePath "C:\path\to\file.txt"`
4. Start PowerShell console transcript: `Start-Transcript C:\path\to\file -UseMinimalHeader`  then `Stop-Transcript`
5. Get drives mounted to PowerShell: `Get-PSDrive`

## Microsoft Attack Surface Reduction Rules
[MS Learn Documentation](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction)
1. Audit Mode: `Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions AuditMode`
2. Block(Audit) Executable content from email client and webmail: `Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions AuditMode`
3. Block (Enabled) Credential Stealing: `Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled`
4. Block (Enabled) vulnerable signed drivers, credential stealing, and persistence through WMI: `Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2, 56a863a9-875e-4185-98a7-b882c64b5ce5, e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled, Enabled, Enabled`
5. Block(Warn) JavaScript and VBScript from launching downloaded executable content: `Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Warn`
6. Block(Enabled) Office from injecting code into other processes: `Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled`

## AZ CLI
1. Log into Azure account: `az login`
2. Start Azure VM: `az vm start -g <Resource Group Name> -n <VM Name>`
3. Deallocate Azure VM: `az vm deallocate -g <Resource Group Name> -n <VM Name>`

## Bash
1. Search Zeek json formatted for indicators:  `for i in 'cat indicators.txt'; do zgrep $i /nsm/zeek/logs/2021-12*/{log}* | jq; done;`
2. Mount VMWare Host share folder to quest: `sudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other`

## Docker
1. Execute command in container: `sudo docker exec <docker name> <Command Arguments>`

## NIDS Rules
1. `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"T1030 - Network Based Data Transfer in Small Chunks"; threshold: type threshold, track by_src, count; 5, seconds 30; dsize:<=1024; classtype:bad-unknown; sid:1319973; rev:1;)`
2. `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"T1030 - Network Based Data Transfer in Small Chunks"; flow:established,to_server; http.content_len; byte_test:0,>=,100000,0,string,dec; classtype:bad-unknown; sid:1319973; rev:1;)`
3. ModBus Write `alert ip any any -> $HOME_NET 502 (msg:"ET Potential Modbus Attack"; flow:established,to_client; modbus:acccess write holding, address 1, value >1; sid:1000000; rev:1;)`
4. ModBus watch registers `alert ip any any-> [OT Subnets] 502 (msg:"ET Potential Modbus Attack"; flow:established,to_client; modbus:acccess write holding, address 1, value >1; sid:1000000; rev:1;)`

## Sigma Rule
```
title: 'DNS Query Greater than 55 characters'
id: 24aa2610-c284-470b-b1c6-5dc64951527c
status: 'experimental'
description: "Identifies DNS queries that are near the 63 character field limit. This could be an indication of data exfiltration."
references:
  - 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md#atomic-test-3---dns-long-domain-query'
author: '@SecurityOnion'
date: '2024/10/16'
tags:
  - detection.threat_hunting
  - attack.exfiltration
  - attack.T1071.004
logsource:
  category: zeek
  product: dns
detection:
    selection:
        - query|gt: 55
    condition: selection
level: 'medium'
    filter:
      query|contains: malware.hash.cymru.
```

## Zeek DNS Filter
```
hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
    {

       # If the query comes back blank don't log
       if (!rec?$query)
          break;

       # If the query comes back with one of these don't log
       if (rec?$query && (/google.com/ | /.apple.com/ | /.microsoft.com/) in rec$query)
           break;

       # Don't log reverse lookups
       if (rec?$query && /.in-addr.arpa/ in to_lower(rec$query))
           break;

       # Don't log netbios lookups. This generates a cray amount of logs
       if (rec?$qtype_name && /NB/ in rec$qtype_name)
           break;
    }

event zeek_init()
{
    Log::remove_default_filter(DNS::LOG);
    local filter: Log::Filter = [$name="dns-filter"];
    Log::add_filter(DNS::LOG, filter);
}
```
