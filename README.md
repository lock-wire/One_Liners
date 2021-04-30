# One_Liners
Single line commands for a variety of shell environments.  I got tired of forgetting them so here they are for all to see.

## PowerShell
1. List Windows Event Logs with data:  `Get-WinEvent -ListLog * | ? {$_.RecordCount -gt 0}`
2. Display command output to console and append to file: `Get-SomeCommand | Tee-Object -FilePath "C:/Someplace/file.txt"`

## AZ CLI
1. Log into Azure account: `az login`
2. Start Azure VM: `az vm start -g <Resource Group Name> -n <VM Name>`
3. Deallocate Azure VM: `az vm deallocate -g <Resource Group Name> -n <VM Name>`

## Bash

## Docker
1. Execute command in container: `sudo docker exec <docker name> <Command Arguments>`

