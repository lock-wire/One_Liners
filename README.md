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


## Docker
1. Execute command in container: `sudo docker exec <docker name> <Command Arguments>`

