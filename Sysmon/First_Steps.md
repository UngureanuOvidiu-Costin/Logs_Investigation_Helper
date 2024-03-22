## Step 1
### Select time frame
```Javascript
Sysmon
| where TimeGenerated >= todatetime('2023-11-12T12:35Z') and TimeGenerated >= todatetime('2023-11-15T00:00Z')
| distinct RenderedDescription
```
### Look for:
- Process accessed
- WmiEventFilter activity detected
- WmiEventConsumer activity detected
- WmiEventConsumerToFilter activity detected
- Powershell(.ps1 script)
- VBS script
- cmd.exe

## Step 2
### Check for processes where malware usually performs injects
- lsass.exe
- svchost.exe
- wuauclt.exe
- Rundll32.exe (Cobalt Strike beacon)
- iexplore.exe
- explorer.exe
- notepad.exe
- vbc.exe
- rdpclip.exe
- logagent.exe
- wermgr.exe
- Mobsync.exe
- Excel.exe
- fwmain32.exe
- regsvcs.exe
- msbuild.exe
- installutil.exe

#### Example for lsass.exe
```Javascript
Sysmon
| where TimeGenerated >= todatetime('2023-11-12T12:35Z') and TimeGenerated <= todatetime('2023-11-15T00:00Z')
| where RenderedDescription has 'Process accessed'
| where target_process_path has 'lsass.exe'
| where process_path !in (@'C\Windows\Sysmon64.exe', @'C:\Program Files (x86\ossec-agent\wazuh-agent.exe)')
```
#### Go and check the possible malware process
```Javascript
Sysmon
| where TimeGenerated >= todatetime('2023-11-12T12:35Z') and TimeGenerated <= todatetime('2023-11-15T00:00Z')
| where RenderedDescription has 'Process create'
| where process_parent_command_line has 'proces_malware.exe'
```
#### Afterward, check the parent process
