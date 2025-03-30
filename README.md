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
Set-TimeZone -Id 'Pacific Standard Time'
# 153. Compare dates
(Get-Date '2025-01-01') -gt (Get-Date)
# 154. Get sunrise/sunset (approx)
Invoke-RestMethod "https://api.sunrise-sunset.org/json?lat=40&lng=-74" | Select-Object -Property sunrise, sunset
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
# 191. Display ASCII art
'Hello' | ForEach-Object { [char[]]$_ | ForEach-Object { Write-Host $_ -NoNewline } }
# 192. Play a beep sound
[Console]::Beep(500, 1000)
# 193. Get clipboard content
Get-Clipboard
# 194. Set clipboard content
'Hello' | Set-Clipboard
# 195. Generate QR code (requires module)
Install-Module -Name QRCodeGenerator; New-QRCode -Content 'https://example.com'
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
(Invoke-RestMethod 'https://api.quotable.io/random').content
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
