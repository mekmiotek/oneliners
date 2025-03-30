# PowerShell Utilities and Commands

A collection of useful PowerShell 1 liners (mostly).

```powershell
# Windows Program Management
# 1. Lists installed programs with details
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Process and DLL Monitoring
# 2. Find processes using a specific DLL
ps | where { $_.Modules.modulename -ieq 'netapi32.dll' }

# Keyboard Automation
# 3. Toggle Caps Lock 10 times with 200ms delay
$wshell = New-Object -ComObject WScript.Shell; 1..10 | ForEach-Object { $wshell.SendKeys("{CAPSLOCK}") ; Start-Sleep -Milliseconds 200 }

# String and Data Manipulation
# 4. Reverse a string
'Hello' | ForEach-Object { $_.ToCharArray() } | ForEach-Object { $r = $_ + $r }; $r
# 5. Convert to uppercase
'hello' | ForEach-Object { $_.ToUpper() }
# 6. Convert to lowercase
'HELLO' | ForEach-Object { $_.ToLower() }
# 7. Count characters in a string
'Hello World'.Length
# 8. Replace text in a string
'Hello World' -replace 'World', 'PowerShell'
# 9. Split a string into array
'a,b,c' -split ','
# 10. Join array into string
('a', 'b', 'c') -join '-'
# 11. Trim whitespace
' Hello ' | ForEach-Object { $_.Trim() }
# 12. Extract substring
'Hello World'.Substring(0,5)
# 13. Check if string contains text
'Hello World' -like '*World*'
# 14. Capitalize first letter
'hello' | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }
# 15. Remove duplicates from array
$a = 1,2,2,3; $a | Sort-Object -Unique
# 16. Pad string with zeros
'42' | ForEach-Object { $_.PadLeft(5, '0') }
# 17. Extract numbers from string
'abc123def' -replace '[^\d]'
# 18. Count vowels in string
('hello' -split '' | Where-Object { $_ -match '[aeiou]' }).Count
# 19. Reverse words in sentence
('Hello World' -split ' ' | ForEach-Object { $r = $_ + ' ' + $r }; $r.Trim())
# 20. Generate GUID
[Guid]::NewGuid().ToString()
# 21. Check if string is palindrome
$s = 'radar'; $s -eq ($s[-1..-($s.Length)] -join '')
# 22. Convert string to ASCII values
'Hello' | ForEach-Object { [int[]][char[]]$_ }
# 23. Mask string (e.g., password)
'password' | ForEach-Object { '*' * $_.Length }
# 24. Reverse array
$a = 1,2,3; [array]::Reverse($a); $a
# 25. Sort array
$a = 3,1,2; $a | Sort-Object
# 26. Count words in text
('Hello world' -split '\s+').Count
# 27. Convert to binary
[Convert]::ToString(42, 2)
# 28. Convert from binary
[Convert]::ToInt32('101010', 2)

# File and Directory Operations
# 29. List all files in directory
Get-ChildItem -Path C:\ -File
# 30. List all directories
Get-ChildItem -Path C:\ -Directory
# 31. Count files in a folder
(Get-ChildItem -Path C:\ -File).Count
# 32. Get file size (MB)
(Get-Item -Path C:\file.txt).Length / 1MB
# 33. Delete files older than 30 days
Get-ChildItem -Path C:\ -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item
# 34. Rename all files in folder
Get-ChildItem -Path C:\ -File | Rename-Item -NewName { $_.Name -replace 'old', 'new' }
# 35. Create a new file
New-Item -Path C:\newfile.txt -ItemType File
# 36. Create a new directory
New-Item -Path C:\newfolder -ItemType Directory
# 37. Read file content
Get-Content -Path C:\file.txt
# 38. Write to a file
'Hello' | Out-File -FilePath C:\file.txt
# 39. List hidden files
Get-ChildItem -Path C:\ -Hidden -File
# 40. Get largest file in folder
Get-ChildItem -Path C:\ -File | Sort-Object Length -Descending | Select-Object -First 1
# 41. Copy files modified today
Get-ChildItem -Path C:\ | Where-Object { $_.LastWriteTime -gt (Get-Date).Date } | Copy-Item -Destination D:\
# 42. Find duplicate files by hash
Get-ChildItem -Path C:\ -File | Group-Object { (Get-FileHash $_.FullName).Hash } | Where-Object { $_.Count -gt 1 }
# 43. Move files by extension
Get-ChildItem -Path C:\ *.txt | Move-Item -Destination C:\TextFiles
# 44. Get folder size (MB)
(Get-ChildItem -Path C:\ -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
# 45. List empty folders
Get-ChildItem -Path C:\ -Directory | Where-Object { (Get-ChildItem $_.FullName) -eq $null }
# 46. Append text to file
'New line' | Add-Content -Path C:\file.txt
# 47. Search file content
Select-String -Path C:\*.txt -Pattern 'error'
# 48. Backup a folder
Copy-Item -Path C:\folder -Destination "C:\backup_$(Get-Date -Format 'yyyyMMdd')" -Recurse
# 49. Compress a folder
Compress-Archive -Path C:\folder -DestinationPath C:\archive.zip
# 50. Extract a zip file
Expand-Archive -Path C:\archive.zip -DestinationPath C:\folder
# 51. Count lines in file
(Get-Content -Path C:\file.txt).Count
# 52. Reverse file content
(Get-Content C:\file.txt) | ForEach-Object { $r = $_ + $r }; $r | Out-File C:\reversed.txt

# System Information
# 53. Get OS version
(Get-CimInstance -ClassName Win32_OperatingSystem).Caption
# 54. Get CPU info
Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores
# 55. Get total RAM (GB)
(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
# 56. Get free disk space (GB)
(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
# 57. Check uptime
(Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
# 58. Get installed software
Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version
# 59. Get motherboard info
Get-CimInstance -ClassName Win32_BaseBoard | Select-Object Manufacturer, Product
# 60. List USB devices
Get-CimInstance -ClassName Win32_USBControllerDevice | ForEach-Object { [wmi]$_.Dependent }
# 61. Get GPU info
Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterRAM
# 62. Check battery status
(Get-CimInstance -ClassName Win32_Battery).BatteryStatus
# 63. Get system boot time
(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
# 64. List environment variables
Get-ChildItem Env:
# 65. Get CPU temperature (if supported)
Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature
# 66. Get BIOS version
(Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
# 67. List hotfixes
Get-HotFix | Select-Object HotFixID, InstalledOn
# 68. Get system serial number
(Get-CimInstance -ClassName Win32_BIOS).SerialNumber
# 69. Check PowerShell version
$PSVersionTable.PSVersion
# 70. Get screen resolution
(Get-CimInstance -ClassName Win32_VideoController).CurrentHorizontalResolution

# Network Utilities
# 71. Get IP address
(Get-NetIPAddress -AddressFamily IPv4).IPAddress
# 72. Test network connection
Test-Connection -ComputerName google.com -Count 4
# 73. Get DNS servers
(Get-DnsClientServerAddress).ServerAddresses
# 74. Flush DNS cache
Clear-DnsClientCache
# 75. Get open ports
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
# 76. Resolve hostname to IP
[System.Net.Dns]::GetHostAddresses('google.com')
# 77. Get MAC address
(Get-NetAdapter).MacAddress
# 78. Check internet speed (simple ping)
Measure-Command { Test-Connection -ComputerName google.com -Count 10 }
# 79. List network adapters
Get-NetAdapter
# 80. Disable a network adapter
Disable-NetAdapter -Name 'Ethernet' -Confirm:$false
# 81. Get default gateway
(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop
# 82. List active connections
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
# 83. Get network usage (bytes sent)
(Get-NetAdapterStatistics).SentBytes
# 84. Enable DHCP on adapter
Set-NetIPInterface -InterfaceAlias 'Ethernet' -Dhcp Enabled
# 85. Set static IP
New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress '192.168.1.100' -PrefixLength 24 -DefaultGateway '192.168.1.1'
# 86. Restart network adapter
Restart-NetAdapter -Name 'Ethernet'
# 87. Get Wi-Fi profiles
netsh wlan show profiles
# 88. Export Wi-Fi profile
netsh wlan export profile name='MyWiFi' folder=C:\
# 89. Get proxy settings
(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
# 90. Trace route
Test-NetConnection -ComputerName google.com -TraceRoute
# 91. Get public IP
(Invoke-RestMethod -Uri 'https://api.ipify.org?format=json').ip

# Process and Task Management
# 92. List all running processes
Get-Process
# 93. Get process CPU usage
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
# 94. Kill a process by name
Stop-Process -Name notepad -Force
# 95. Start a process
Start-Process -FilePath notepad.exe
# 96. Get process memory usage (MB)
Get-Process | Select-Object Name, @{Name='MemoryMB';Expression={$_.WorkingSet/1MB}}
# 97. List processes by memory usage
Get-Process | Sort-Object WS -Descending | Select-Object -First 5
# 98. Restart a service
Restart-Service -Name spooler
# 99. Stop a service
Stop-Service -Name spooler -Force
# 100. Start a service
Start-Service -Name spooler
# 101. Get scheduled tasks
Get-ScheduledTask
# 102. Run a task now
Start-ScheduledTask -TaskName 'MyTask'
# 103. Disable a scheduled task
Disable-ScheduledTask -TaskName 'MyTask'
# 104. Kill processes over 1GB memory
Get-Process | Where-Object { $_.WS -gt 1GB } | Stop-Process -Force
# 105. List processes by company
Get-Process | Group-Object Company
# 106. Get process start time
(Get-Process -Name notepad).StartTime
# 107. Run command as another user
Start-Process -FilePath cmd.exe -Credential (Get-Credential)
# 108. Get service dependencies
Get-Service -Name spooler -RequiredServices
# 109. List services by start type
Get-Service | Group-Object StartType
# 110. Create scheduled task (daily)
Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'notepad') -Trigger (New-ScheduledTaskTrigger -Daily -At '9AM') -TaskName 'DailyNote'
# 111. Export scheduled tasks
Get-ScheduledTask | Export-ScheduledTask
# 112. Get process path
(Get-Process -Name notepad).Path
# 113. Monitor process start
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action { Write-Host "$($event.SourceEventArgs.NewEvent.ProcessName) started" }
# 114. List all services
Get-Service
# 115. Get running services
Get-Service | Where-Object { $_.Status -eq 'Running' }

# User and Security
# 116. Get current user
$env:USERNAME
# 117. List all local users
Get-LocalUser
# 118. Create a new local user
New-LocalUser -Name 'TestUser' -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
# 119. Add user to admin group
Add-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
# 120. Get logged-on users
query user
# 121. Lock the workstation
rundll32.exe user32.dll,LockWorkStation
# 122. Log off current user
logoff
# 123. Get password expiration date
(Get-LocalUser -Name $env:USERNAME).PasswordExpires
# 124. List group memberships
Get-LocalGroupMember -Group 'Administrators'
# 125. Check if running as admin
[Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
# 126. List all groups
Get-LocalGroup
# 127. Remove user from group
Remove-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
# 128. Get SID of current user
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# 129. Enable guest account
Enable-LocalUser -Name 'Guest'
# 130. Disable UAC (requires restart)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0
# 131. Get firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
# 132. Block IP in firewall
New-NetFirewallRule -Name 'BlockIP' -Direction Inbound -Action Block -RemoteAddress '192.168.1.100'
# 133. Get BitLocker status
(Get-BitLockerVolume -MountPoint C:).ProtectionStatus
# 134. List shadow copies
Get-CimInstance -ClassName Win32_ShadowCopy
# 135. Create shadow copy
wmic shadowcopy create Volume=C:\

# Date and Time
# 136. Get current date/time
Get-Date
# 137. Add days to current date
(Get-Date).AddDays(7)
# 138. Format date as YYYY-MM-DD
Get-Date -Format 'yyyy-MM-dd'
# 139. Get timestamp
(Get-Date).ToFileTime()
# 140. Convert Unix timestamp to date
[DateTimeOffset]::FromUnixTimeSeconds(1640995200).DateTime
# 141. Get day of the week
(Get-Date).DayOfWeek
# 142. Set system time
Set-Date -Date '2025-03-08 12:00:00'
# 143. Get time zone
(Get-TimeZone).Id
# 144. Calculate time difference
(Get-Date) - (Get-Date '2025-01-01')
# 145. Get elapsed time of command
Measure-Command { Start-Sleep -Seconds 2 }
# 146. Get UTC time
(Get-Date).ToUniversalTime()
# 147. Subtract hours
(Get-Date).AddHours(-3)
# 148. Get first day of month
(Get-Date -Day 1).Date
# 149. Get last day of month
(Get-Date -Day 1).AddMonths(1).AddDays(-1).Date
# 150. Convert to epoch seconds
[int64]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
# 151. Get week number
(Get-Date).DayOfYear / 7 -as [int]
# 152. Set time zone
Set-TimeZone -Id 'Eastern Standard Time'
# 153. Compare dates
(Get-Date '2025-01-01') -gt (Get-Date)
# 154. Get sunrise/sunset (approx)
Invoke-RestMethod "https://api.sunrise-sunset.org/json?lat=40&lng=-74" | Select-Object -ExpandProperty results | Select-Object @{Name='sunrise';Expression={[datetime]::Parse($_.sunrise, [System.Globalization.CultureInfo]::InvariantCulture).AddHours(-4)}}, @{Name='sunset';Expression={[datetime]::Parse($_.sunset, [System.Globalization.CultureInfo]::InvariantCulture).AddHours(-4)}}
# 155. Log time to file
Get-Date | Out-File -FilePath C:\log.txt -Append

# Miscellaneous Utilities
# 156. Generate random number
Get-Random -Minimum 1 -Maximum 100
# 157. Generate random password
-join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
# 158. Convert to JSON
@{Name='Test';Value=123} | ConvertTo-Json
# 159. Convert from JSON
'{"Name":"Test","Value":123}' | ConvertFrom-Json
# 160. Base64 encode
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Hello'))
# 161. Base64 decode
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8='))
# 162. Calculate hash (SHA256)
(Get-FileHash -Path C:\file.txt -Algorithm SHA256).Hash
# 163. Speak text aloud
Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Hello')
# 164. Generate random color hex
'#{0:X6}' -f (Get-Random -Minimum 0 -Maximum 16777215)
# 165. Convert CSV to object
Import-Csv -Path C:\data.csv
# 166. Export to CSV
Get-Process | Export-Csv -Path C:\processes.csv -NoTypeInformation
# 167. Encrypt a file
Protect-CmsMessage -To '*self*' -Content (Get-Content C:\file.txt -Raw) | Out-File C:\encrypted.txt
# 168. Decrypt a file
Unprotect-CmsMessage -Path C:\encrypted.txt | Out-File C:\decrypted.txt
# 169. Generate lorem ipsum
-join ((65..90) | Get-Random -Count 50 | ForEach-Object { [char]$_ })
# 170. Create shortcut
New-Item -ItemType SymbolicLink -Path C:\link -Target C:\target

# System Maintenance
# 171. Clear recycle bin
Clear-RecycleBin -Force
# 172. Get event logs (errors)
Get-EventLog -LogName System -EntryType Error -Newest 10
# 173. Restart computer
Restart-Computer -Force
# 174. Shutdown computer
Stop-Computer -Force
# 175. Check disk health
Get-Disk | Select-Object Number, FriendlyName, HealthStatus
# 176. Repair disk errors
Repair-Volume -DriveLetter C -Scan
# 177. Defragment drive
Optimize-Volume -DriveLetter C
# 178. Get Windows updates
Get-WindowsUpdate
# 179. Install all updates
Install-WindowsUpdate -AcceptAll
# 180. Clear temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
# 181. Get pending reboots
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').RebootRequired
# 182. List installed drivers
Get-WindowsDriver -Online
# 183. Uninstall software
Get-CimInstance -ClassName Win32_Product -Filter "Name='AppName'" | Invoke-CimMethod -MethodName Uninstall
# 184. Clear event log
Clear-EventLog -LogName Application
# 185. Get system uptime in days
((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).Days
# 186. Check memory usage %
100 * (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
# 187. List startup programs
Get-CimInstance -ClassName Win32_StartupCommand
# 188. Disable startup program
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ProgramName'
# 189. Get disk SMART status
(Get-Disk).OperationalStatus
# 190. Run disk cleanup
cleanmgr /sagerun:1

# Fun and Cool Tricks
# 191. Create starfield pattern with *
1..10 | ForEach-Object { Write-Host (" " * (Get-Random -Max 20) + "*" * (Get-Random -Min 1 -Max 5)) }
# 192. Play a beep sound
[Console]::Beep(500, 1000)
# 193. Get clipboard content
Get-Clipboard
# 194. Set clipboard content
'Hello' | Set-Clipboard
# 195. Generate QR code (requires module)
Install-Module -Name QRCodeGenerator; New-QRCode -Content 'https://example.com' -FilePath 'c:\temp\examplecomqrcode.png'
# 196. Display a progress bar
1..100 | ForEach-Object { Write-Progress -Activity 'Processing' -Status "$_%" -PercentComplete $_; Start-Sleep -Milliseconds 50 }
# 197. Display rainbow text
'Hello' | ForEach-Object { $i=0; [char[]]$_ | ForEach-Object { Write-Host $_ -ForegroundColor ($i++ % 15) -NoNewline } }
# 198. Play a tune (beeps)
500,300,400,200 | ForEach-Object { [Console]::Beep($_, 200) }
# 199. Get weather (simple)
(Invoke-RestMethod "wttr.in?format=3").Trim()
# 200. Simulate typing
'Hello' | ForEach-Object { $_.ToCharArray() | ForEach-Object { [Console]::Write($_); Start-Sleep -Milliseconds 100 } }
# 201. Get random quote
(Invoke-RestMethod 'https://api.quotable.io/random' -SkipCertificateCheck).content
# 202. List fonts
(New-Object System.Drawing.Text.InstalledFontCollection).Families
# 203. Flash console window
1..5 | ForEach-Object { 
    $originalBackground = [Console]::BackgroundColor
    $originalForeground = [Console]::ForegroundColor
    [Console]::BackgroundColor = 'White'
    [Console]::ForegroundColor = 'Black'
    Clear-Host  # Redraws the screen with new colors
    Start-Sleep -Milliseconds 100
    [Console]::BackgroundColor = $originalBackground
    [Console]::ForegroundColor = $originalForeground
    Clear-Host  # Restores original colors
    Start-Sleep -Milliseconds 200
}
Registry Operations
204. List all registry keys in a path - Get-ChildItem -Path HKLM:\Software
205. Create a new registry key - New-Item -Path HKLM:\Software\MyApp -Force
206. Set a registry value - Set-ItemProperty -Path HKLM:\Software\MyApp -Name "Version" -Value "1.0"
207. Get a specific registry value - (Get-ItemProperty -Path HKLM:\Software\MyApp).Version
208. Delete a registry key - Remove-Item -Path HKLM:\Software\MyApp -Recurse -Force
209. Check if a registry key exists - Test-Path -Path HKLM:\Software\MyApp
210. Export registry key to file - reg export HKLM\Software\MyApp C:\backup.reg
211. Import registry key from file - reg import C:\backup.reg
212. List subkeys of a registry key - (Get-Item -Path HKLM:\Software).GetSubKeyNames()
213. Backup a registry hive - reg save HKLM\Software C:\software.hiv

PowerShell Profiles and Modules
214. Open PowerShell profile for editing - notepad $PROFILE
215. Reload PowerShell profile - . $PROFILE
216. List all installed PowerShell modules - Get-Module -ListAvailable
217. Install a PowerShell module from gallery - Install-Module -Name Pester -Force
218. Update a specific PowerShell module - Update-Module -Name Pester
219. Uninstall a PowerShell module - Uninstall-Module -Name Pester
220. Get commands in a module - Get-Command -Module Pester
221. Import a module manually - Import-Module -Name C:\Modules\MyModule.psm1
222. Create a new PowerShell module manifest - New-ModuleManifest -Path C:\Modules\MyModule.psd1
223. List all PowerShell sessions - Get-PSSession

Event and Logging
224. Create a new event log source - New-EventLog -LogName Application -Source MyApp
225. Write to event log - Write-EventLog -LogName Application -Source MyApp -EventId 1000 -Message "Test event"
226. Get latest 5 application logs - Get-EventLog -LogName Application -Newest 5
227. Export event logs to CSV - Get-EventLog -LogName System | Export-Csv -Path C:\systemlogs.csv -NoTypeInformation
228. Clear all event logs - Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }
229. Monitor event log for new entries - Register-EngineEvent -SourceIdentifier "NewEvent" -Action { Write-Host "New event detected!" }
230. Get event log sources - (Get-EventLog -LogName Application).Entries | Select-Object -ExpandProperty Source -Unique
231. Search event logs by message - Get-EventLog -LogName System | Where-Object { $_.Message -like "*error*" }
232. Get event log entry by ID - Get-EventLog -LogName System | Where-Object { $_.EventID -eq 1000 }
233. List event log categories - (Get-EventLog -LogName System).Entries | Select-Object -ExpandProperty Category -Unique

Performance Monitoring
234. Get CPU usage percentage - (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
235. Monitor memory usage over time - 1..5 | ForEach-Object { (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue; Start-Sleep -Seconds 1 }
236. List top 5 processes by handle count - Get-Process | Sort-Object HandleCount -Descending | Select-Object -First 5
237. Get disk I/O statistics - (Get-Counter '\PhysicalDisk(_Total)\Disk Bytes/sec').CounterSamples.CookedValue
238. Check network bandwidth usage - (Get-Counter '\Network Interface(*)\Bytes Total/sec').CounterSamples.CookedValue
239. Get system performance counters - Get-Counter -ListSet * | Select-Object CounterSetName
240. Monitor a specific counter - Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 3
241. Export performance data to file - Get-Counter -Counter '\Processor(_Total)\% Processor Time' | Export-Counter -Path C:\perf.blg
242. Get system idle time - (Get-Counter '\System\System Up Time').CounterSamples.CookedValue
243. List processes with high CPU usage - Get-Process | Where-Object { $_.CPU -gt 1000 }

Remote Management
244. Connect to a remote PowerShell session - Enter-PSSession -ComputerName RemotePC
245. Run a command on a remote computer - Invoke-Command -ComputerName RemotePC -ScriptBlock { Get-Process }
246. Copy a file to a remote computer - Copy-Item -Path C:\file.txt -Destination \\RemotePC\C$\file.txt
247. Restart a remote computer - Restart-Computer -ComputerName RemotePC -Force
248. Get remote system info - Invoke-Command -ComputerName RemotePC -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem }
249. Enable PSRemoting on a remote machine - Enable-PSRemoting -Force
250. List all remote sessions - Get-PSSession | Select-Object ComputerName, State
251. Disconnect a remote session - Disconnect-PSSession -Name Session1
252. Run a script on multiple remote PCs - Invoke-Command -ComputerName PC1,PC2 -FilePath C:\script.ps1
253. Check remote computer uptime - Invoke-Command -ComputerName RemotePC -ScriptBlock { (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime }

Advanced File Operations
254. Find files larger than 100MB - Get-ChildItem -Path C:\ -File | Where-Object { $_.Length -gt 100MB }
255. List files by creation date - Get-ChildItem -Path C:\ | Sort-Object CreationTime
256. Replace text in multiple files - Get-ChildItem -Path C:\*.txt | ForEach-Object { (Get-Content $_.FullName) -replace 'old', 'new' | Set-Content $_.FullName }
257. Get file encoding - (Get-Content -Path C:\file.txt -Raw | Select-String .).Encoding
258. Convert file encoding to UTF-8 - Get-Content -Path C:\file.txt | Set-Content -Path C:\file_utf8.txt -Encoding UTF8
259. List files with specific attributes - Get-ChildItem -Path C:\ -File | Where-Object { $_.Attributes -match 'ReadOnly' }
260. Lock a file (prevent access) - $file = [System.IO.File]::Open('C:\file.txt', 'Open', 'Read', 'None')
261. Unlock a file - $file.Close()
262. Get file version info - (Get-Item -Path C:\file.exe).VersionInfo
263. Split a large file into parts - $content = Get-Content -Path C:\largefile.txt; $chunkSize = 1000; for ($i = 0; $i -lt $content.Count; $i += $chunkSize) { $content[$i..($i + $chunkSize - 1)] | Out-File "C:\part$($i / $chunkSize).txt" }

System Configuration
264. Enable Remote Desktop - Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
265. Disable Remote Desktop - Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
266. Set power plan to high performance - powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
267. List all power plans - powercfg /list
268. Change screen brightness (0-100) - (Get-WmiObject -Namespace root\WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1, 50)
269. Disable Windows Defender real-time protection - Set-MpPreference -DisableRealtimeMonitoring $true
270. Enable Windows Defender real-time protection - Set-MpPreference -DisableRealtimeMonitoring $false
271. Set wallpaper - Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'Wallpaper' -Value 'C:\wallpaper.jpg'; rundll32.exe user32.dll, UpdatePerUserSystemParameters
272. Get current power state - (Get-CimInstance -ClassName Win32_ComputerSystem).PowerState
273. Enable firewall - Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Security and Encryption
274. Generate a self-signed certificate - New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "Cert:\LocalMachine\My"
275. Export a certificate to file - Export-Certificate -Cert (Get-Item Cert:\LocalMachine\My\Thumbprint) -FilePath C:\cert.cer
276. Import a certificate - Import-Certificate -FilePath C:\cert.cer -CertStoreLocation Cert:\LocalMachine\My
277. List all certificates in store - Get-ChildItem -Path Cert:\LocalMachine\My
278. Encrypt a string with AES - $key = (1..32); $encrypted = ConvertTo-SecureString 'Secret' -AsPlainText -Force | ConvertFrom-SecureString -Key $key; $encrypted
279. Decrypt an AES-encrypted string - $key = (1..32); $decrypted = ConvertTo-SecureString $encrypted -Key $key | ConvertFrom-SecureString -AsPlainText; $decrypted
280. Get current user’s security token - [System.Security.Principal.WindowsIdentity]::GetCurrent().AccessToken
281. List all security policies - Get-CimInstance -ClassName Win32_SecuritySetting
282. Enable secure boot (if supported) - Confirm-SecureBootUEFI
283. Check if TPM is enabled - (Get-WmiObject -Namespace root\cimv2\Security\MicrosoftTpm -Class Win32_Tpm).IsEnabled()

Automation and Scripting
284. Create a script to run at startup - $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\script.ps1'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'StartupScript' -Action $action -Trigger $trigger
285. List all aliases - Get-Alias
286. Create a new alias - Set-Alias -Name ll -Value Get-ChildItem
287. Remove an alias - Remove-Item -Path Alias:ll
288. Get command history - Get-History
289. Export command history to file - Get-History | Export-Clixml -Path C:\history.xml
290. Import command history from file - Import-Clixml -Path C:\history.xml | Add-History
291. Clear command history - Clear-History
292. Run a command with elevated privileges - Start-Process powershell -Verb RunAs -ArgumentList '-Command "Get-Process"'
293. Create a transcript of session - Start-Transcript -Path C:\transcript.txt

Advanced Network Operations
294. Get current network profile - (Get-NetConnectionProfile).NetworkCategory
295. Set network profile to private - Set-NetConnectionProfile -InterfaceAlias 'Ethernet' -NetworkCategory Private
296. Enable network discovery - Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled True
297. Disable network discovery - Set-NetFirewallRule -DisplayGroup 'Network Discovery' -Enabled False
298. Get network latency to a host - (Test-Connection -ComputerName google.com -Count 1).ResponseTime
299. List all network shares - Get-SmbShare
300. Create a new network share - New-SmbShare -Name 'MyShare' -Path 'C:\Shared' -FullAccess Everyone
301. Remove a network share - Remove-SmbShare -Name 'MyShare' -Force
302. Get current VPN connections - Get-VpnConnection
303. Disconnect a VPN connection - Disconnect-VpnConnection -Name 'MyVPN'

Fun and Cool Tricks (Continued)
304. Display a random ASCII art animal - $animals = '🐶','🐱','🐻'; Write-Host ($animals | Get-Random)
305. Create a simple GUI message box - Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Hello, World!')
306. Play a WAV file - (New-Object System.Media.SoundPlayer 'C:\sound.wav').PlaySync()
307. Get a random emoji - $emojis = '😀','😂','😍'; $emojis | Get-Random
308. Create a simple timer - $seconds = 10; 1..$seconds | ForEach-Object { Write-Host "$($seconds - $_) seconds remaining"; Start-Sleep -Seconds 1 }; Write-Host "Time's up!"
309. Display a random color in console - $color = Get-Random -Minimum 1 -Maximum 15; Write-Host "Random Color!" -ForegroundColor $color
310. Simulate a matrix-like effect - # Set console to mimic Matrix aesthetic
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Green"
Clear-Host

# Get console width for full-screen effect
$width = $Host.UI.RawUI.WindowSize.Width

# Run indefinitely (Ctrl+C to stop)
while ($true) {
    # Array to hold character positions
    $line = @(" " * $width).ToCharArray()
    
    # Randomly place "falling" character streams
    $columns = Get-Random -Minimum 5 -Maximum 15
    for ($i = 0; $i -lt $columns; $i++) {
        $pos = Get-Random -Minimum 0 -Maximum ($width - 1)
        $chars = (48..57) + (65..90) + (97..122) # Numbers, uppercase, lowercase
        $line[$pos] = [char](Get-Random -InputObject $chars)
    }
    
    # Print the line and pause briefly
    Write-Host (-join $line) -ForegroundColor Green -NoNewline
    Write-Host "" # New line
    Start-Sleep -Milliseconds 50 # Faster for smoother effect
}
