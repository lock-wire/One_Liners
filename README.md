# One_Liners
Single line commands for a variety of shell environments.  I got tired of forgetting them so here they are for all to see.

## PowerShell
1. List Windows Event Logs with data:  `Get-WinEvent -ListLog * | ? {$_.RecordCount -gt 0}`
2. Write to file: `Write-Output "foo" | Out-File C:\path\to\file`
3. Display command output to console and append to file: `Get-SomeCommand | Tee-Object -FilePath "C:\path\to\file.txt"`
4. Start PowerShell console transcript: `Start-Transcript C:\path\to\file -UseMinimalHeader`  then `Stop-Transcript`
5. Get drives mounted to PowerShell: `Get-PSDrive`

## AZ CLI
1. Log into Azure account: `az login`
2. Start Azure VM: `az vm start -g <Resource Group Name> -n <VM Name>`
3. Deallocate Azure VM: `az vm deallocate -g <Resource Group Name> -n <VM Name>`

## Bash
1. Search Zeek json formatted for indicators:  `for i in 'cat indicators.txt'; do zgrep $i /nsm/zeek/logs/2021-12*/{log}* | jq; done;`


## Docker
1. Execute command in container: `sudo docker exec <docker name> <Command Arguments>`

