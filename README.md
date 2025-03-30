Windows Program Management
1. Lists installed programs with details - Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
Process and DLL Monitoring
2. Find processes using a specific DLL - ps | where { $_.Modules.modulename -ieq 'netapi32.dll' }
3. Keyboard Automation
4. Toggle Caps Lock 10 times with 200ms delay - $wshell = New-Object -ComObject WScript.Shell; 1..10 | ForEach-Object { $wshell.SendKeys("{CAPSLOCK}") ; Start-Sleep -Milliseconds 200 }
String and Data Manipulation
5. Reverse a string - 'Hello' | ForEach-Object { $_.ToCharArray() } | ForEach-Object { $r = $_ + $r }; $r
6. Convert to uppercase - 'hello' | ForEach-Object { $_.ToUpper() }
7. Convert to lowercase - 'HELLO' | ForEach-Object { $_.ToLower() }
8. Count characters in a string - 'Hello World'.Length
9. Replace text in a string - 'Hello World' -replace 'World', 'PowerShell'
10. Split a string into array - 'a,b,c' -split ','
11. Join array into string - ('a', 'b', 'c') -join '-'
12. Trim whitespace - ' Hello ' | ForEach-Object { $_.Trim() }
13. Extract substring - 'Hello World'.Substring(0,5)
14. Check if string contains text - 'Hello World' -like '*World*'
15. Capitalize first letter - 'hello' | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }
16. Remove duplicates from array - $a = 1,2,2,3; $a | Sort-Object -Unique
17. Pad string with zeros - '42' | ForEach-Object { $_.PadLeft(5, '0') }
18. Extract numbers from string - 'abc123def' -replace '[^\d]'
19. Count vowels in string - ('hello' -split '' | Where-Object { $_ -match '[aeiou]' }).Count
20. Reverse words in sentence - ('Hello World' -split ' ' | ForEach-Object { $r = $_ + ' ' + $r }; $r.Trim())
21. Generate GUID - [Guid]::NewGuid().ToString()
22. Check if string is palindrome - $s = 'radar'; $s -eq ($s[-1..-($s.Length)] -join '')
23. Convert string to ASCII values - 'Hello' | ForEach-Object { [int[]][char[]]$_ }
24. Mask string (e.g., password) - 'password' | ForEach-Object { '*' * $_.Length }
25. Reverse array - $a = 1,2,3; [array]::Reverse($a); $a
26. Sort array - $a = 3,1,2; $a | Sort-Object
27. Count words in text - ('Hello world' -split '\s+').Count
28. Convert to binary - [Convert]::ToString(42, 2)
29. Convert from binary - [Convert]::ToInt32('101010', 2)
File and Directory Operations
30. List all files in directory - Get-ChildItem -Path C:\ -File
31. List all directories - Get-ChildItem -Path C:\ -Directory
32. Count files in a folder - (Get-ChildItem -Path C:\ -File).Count
33. Get file size (MB) - (Get-Item -Path C:\file.txt).Length / 1MB
34. Delete files older than 30 days - Get-ChildItem -Path C:\ -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item
35. Rename all files in folder - Get-ChildItem -Path C:\ -File | Rename-Item -NewName { $_.Name -replace 'old', 'new' }
36. Create a new file - New-Item -Path C:\newfile.txt -ItemType File
37. Create a new directory - New-Item -Path C:\newfolder -ItemType Directory
38. Read file content - Get-Content -Path C:\file.txt
39. Write to a file - 'Hello' | Out-File -FilePath C:\file.txt
40. List hidden files - Get-ChildItem -Path C:\ -Hidden -File
41. Get largest file in folder - Get-ChildItem -Path C:\ -File | Sort-Object Length -Descending | Select-Object -First 1
42. Copy files modified today - Get-ChildItem -Path C:\ | Where-Object { $_.LastWriteTime -gt (Get-Date).Date } | Copy-Item -Destination D:\
43. Find duplicate files by hash - Get-ChildItem -Path C:\ -File | Group-Object { (Get-FileHash $_.FullName).Hash } | Where-Object { $_.Count -gt 1 }
44. Move files by extension - Get-ChildItem -Path C:\ *.txt | Move-Item -Destination C:\TextFiles
45. Get folder size (MB) - (Get-ChildItem -Path C:\ -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
46. List empty folders - Get-ChildItem -Path C:\ -Directory | Where-Object { (Get-ChildItem $_.FullName) -eq $null }
47. Append text to file - 'New line' | Add-Content -Path C:\file.txt
48. Search file content - Select-String -Path C:\*.txt -Pattern 'error'
49. Backup a folder - Copy-Item -Path C:\folder -Destination "C:\backup_$(Get-Date -Format 'yyyyMMdd')" -Recurse
50. Compress a folder - Compress-Archive -Path C:\folder -DestinationPath C:\archive.zip
51. Extract a zip file - Expand-Archive -Path C:\archive.zip -DestinationPath C:\folder
52. Count lines in file - (Get-Content -Path C:\file.txt).Count
53. Reverse file content - (Get-Content C:\file.txt) | ForEach-Object { $r = $_ + $r }; $r | Out-File C:\reversed.txt
System Information
54. Get OS version - (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
55. Get CPU info - Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores
56. Get total RAM (GB) - (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
57. Get free disk space (GB) - (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
58. Check uptime - (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
59. Get installed software - Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version
60. Get motherboard info - Get-CimInstance -ClassName Win32_BaseBoard | Select-Object Manufacturer, Product
61. List USB devices - Get-CimInstance -ClassName Win32_USBControllerDevice | ForEach-Object { [wmi]$_.Dependent }
62. Get GPU info - Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterRAM
63. Check battery status - (Get-CimInstance -ClassName Win32_Battery).BatteryStatus
64. Get system boot time - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
65. List environment variables - Get-ChildItem Env:
66. Get CPU temperature (if supported) - Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature
67. Get BIOS version - (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
68. List hotfixes - Get-HotFix | Select-Object HotFixID, InstalledOn
69. Get system serial number - (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
70. Check PowerShell version - $PSVersionTable.PSVersion
71. Get screen resolution - (Get-CimInstance -ClassName Win32_VideoController).CurrentHorizontalResolution
Network Utilities
72. Get IP address - (Get-NetIPAddress -AddressFamily IPv4).IPAddress
73. Test network connection - Test-Connection -ComputerName google.com -Count 4
74. Get DNS servers - (Get-DnsClientServerAddress).ServerAddresses
75. Flush DNS cache - Clear-DnsClientCache
76. Get open ports - Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
77. Resolve hostname to IP - [System.Net.Dns]::GetHostAddresses('google.com')
78. Get MAC address - (Get-NetAdapter).MacAddress
79. Check internet speed (simple ping) - Measure-Command { Test-Connection -ComputerName google.com -Count 10 }
80. List network adapters - Get-NetAdapter
81. Disable a network adapter - Disable-NetAdapter -Name 'Ethernet' -Confirm:$false
82. Get default gateway - (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop
83. List active connections - Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
84. Get network usage (bytes sent) - (Get-NetAdapterStatistics).SentBytes
85. Enable DHCP on adapter - Set-NetIPInterface -InterfaceAlias 'Ethernet' -Dhcp Enabled
86. Set static IP - New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress '192.168.1.100' -PrefixLength 24 -DefaultGateway '192.168.1.1'
87. Restart network adapter - Restart-NetAdapter -Name 'Ethernet'
88. Get Wi-Fi profiles - netsh wlan show profiles
89. Export Wi-Fi profile - netsh wlan export profile name='MyWiFi' folder=C:\
90. Get proxy settings - (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
91. Trace route - Test-NetConnection -ComputerName google.com -TraceRoute
92. Get public IP - (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json').ip
Process and Task Management
93. List all running processes - Get-Process
94. Get process CPU usage - Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
95. Kill a process by name - Stop-Process -Name notepad -Force
96. Start a process - Start-Process -FilePath notepad.exe
97. Get process memory usage (MB) - Get-Process | Select-Object Name, @{Name='MemoryMB';Expression={$_.WorkingSet/1MB}}
98. List processes by memory usage - Get-Process | Sort-Object WS -Descending | Select-Object -First 5
99. Restart a service - Restart-Service -Name spooler
100. Stop a service - Stop-Service -Name spooler -Force
101. Start a service - Start-Service -Name spooler
102. Get scheduled tasks - Get-ScheduledTask
103. Run a task now - Start-ScheduledTask -TaskName 'MyTask'
104. Disable a scheduled task - Disable-ScheduledTask -TaskName 'MyTask'
105. Kill processes over 1GB memory - Get-Process | Where-Object { $_.WS -gt 1GB } | Stop-Process -Force
106. List processes by company - Get-Process | Group-Object Company
107. Get process start time - (Get-Process -Name notepad).StartTime
108. Run command as another user - Start-Process -FilePath cmd.exe -Credential (Get-Credential)
109. Get service dependencies - Get-Service -Name spooler -RequiredServices
110. List services by start type - Get-Service | Group-Object StartType
111. Create scheduled task (daily) - Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'notepad') -Trigger (New-ScheduledTaskTrigger -Daily -At '9AM') -TaskName 'DailyNote'
112. Export scheduled tasks - Get-ScheduledTask | Export-ScheduledTask
113. Get process path - (Get-Process -Name notepad).Path
114. Monitor process start - Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action { Write-Host "$($event.SourceEventArgs.NewEvent.ProcessName) started" }
115. List all services - Get-Service
116. Get running services - Get-Service | Where-Object { $_.Status -eq 'Running' }
User and Security
117. Get current user - $env:USERNAME
118. List all local users - Get-LocalUser
119. Create a new local user - New-LocalUser -Name 'TestUser' -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
120. Add user to admin group - Add-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
121. Get logged-on users - query user
122. Lock the workstation - rundll32.exe user32.dll,LockWorkStation
123. Log off current user - logoff
124. Get password expiration date - (Get-LocalUser -Name $env:USERNAME).PasswordExpires
125. List group memberships - Get-LocalGroupMember -Group 'Administrators'
126. Check if running as admin - [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
127. List all groups - Get-LocalGroup
128. Remove user from group - Remove-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
129. Get SID of current user - [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
130. Enable guest account - Enable-LocalUser -Name 'Guest'
131. Disable UAC (requires restart) - Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0
132. Get firewall rules - Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
133. Block IP in firewall - New-NetFirewallRule -Name 'BlockIP' -Direction Inbound -Action Block -RemoteAddress '192.168.1.100'
134. Get BitLocker status - (Get-BitLockerVolume -MountPoint C:).ProtectionStatus
135. List shadow copies - Get-CimInstance -ClassName Win32_ShadowCopy
136. Create shadow copy - wmic shadowcopy create Volume=C:\
Date and Time
137. Get current date/time - Get-Date
138. Add days to current date - (Get-Date).AddDays(7)
139. Format date as YYYY-MM-DD - Get-Date -Format 'yyyy-MM-dd'
140. Get timestamp - (Get-Date).ToFileTime()
141. Convert Unix timestamp to date - [DateTimeOffset]::FromUnixTimeSeconds(1640995200).DateTime
142. Get day of the week - (Get-Date).DayOfWeek
143. Set system time - Set-Date -Date '2025-03-08 12:00:00'
144. Get time zone - (Get-TimeZone).Id
145. Calculate time difference - (Get-Date) - (Get-Date '2025-01-01')
146. Get elapsed time of command - Measure-Command { Start-Sleep -Seconds 2 }
147. Get UTC time - (Get-Date).ToUniversalTime()
148. Subtract hours - (Get-Date).AddHours(-3)
149. Get first day of month - (Get-Date -Day 1).Date
150. Get last day of month - (Get-Date -Day 1).AddMonths(1).AddDays(-1).Date
151. Convert to epoch seconds - [int64]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
152. Get week number - (Get-Date).DayOfYear / 7 -as [int]
153. Set time zone - Set-TimeZone -Id 'Pacific Standard Time'
154. Compare dates - (Get-Date '2025-01-01') -gt (Get-Date)
155. Get sunrise/sunset (approx) - Invoke-RestMethod "https://api.sunrise-sunset.org/json?lat=40&lng=-74" | Select-Object -Property sunrise, sunset
156. Log time to file - Get-Date | Out-File -FilePath C:\log.txt -Append
Miscellaneous Utilities
157. Generate random number - Get-Random -Minimum 1 -Maximum 100
158. Generate random password - -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
159. Convert to JSON - @{Name='Test';Value=123} | ConvertTo-Json
160. Convert from JSON - '{"Name":"Test","Value":123}' | ConvertFrom-Json
161. Base64 encode - [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Hello'))
162. Base64 decode - [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8='))
163. Calculate hash (SHA256) - (Get-FileHash -Path C:\file.txt -Algorithm SHA256).Hash
164. Speak text aloud - Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Hello')
165. Generate random color hex - '#{0:X6}' -f (Get-Random -Minimum 0 -Maximum 16777215)
166. Convert CSV to object - Import-Csv -Path C:\data.csv
167. Export to CSV - Get-Process | Export-Csv -Path C:\processes.csv -NoTypeInformation
168. Encrypt a file - Protect-CmsMessage -To '*self*' -Content (Get-Content C:\file.txt -Raw) | Out-File C:\encrypted.txt
169. Decrypt a file - Unprotect-CmsMessage -Path C:\encrypted.txt | Out-File C:\decrypted.txt
170. Generate lorem ipsum - -join ((65..90) | Get-Random -Count 50 | ForEach-Object { [char]$_ })
171. Create shortcut - New-Item -ItemType SymbolicLink -Path C:\link -Target C:\target
System Maintenance
172. Clear recycle bin - Clear-RecycleBin -Force
173. Get event logs (errors) - Get-EventLog -LogName System -EntryType Error -Newest 10
174. Restart computer - Restart-Computer -Force
175. Shutdown computer - Stop-Computer -Force
176. Check disk health - Get-Disk | Select-Object Number, FriendlyName, HealthStatus
177. Repair disk errors - Repair-Volume -DriveLetter C -Scan
178. Defragment drive - Optimize-Volume -DriveLetter C
179. Get Windows updates - Get-WindowsUpdate
180. Install all updates - Install-WindowsUpdate -AcceptAll
181. Clear temp files - Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
182. Get pending reboots - (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').RebootRequired
183. List installed drivers - Get-WindowsDriver -Online
184. Uninstall software - Get-CimInstance -ClassName Win32_Product -Filter "Name='AppName'" | Invoke-CimMethod -MethodName Uninstall
185. Clear event log - Clear-EventLog -LogName Application
186. Get system uptime in days - ((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).Days
187. Check memory usage % - 100 * (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
188. List startup programs - Get-CimInstance -ClassName Win32_StartupCommand
189. Disable startup program - Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ProgramName'
190. Get disk SMART status - (Get-Disk).OperationalStatus
191. Run disk cleanup - cleanmgr /sagerun:1
Fun and Cool Tricks
192. Display ASCII art - 'Hello' | ForEach-Object { [char[]]$_ | ForEach-Object { Write-Host $_ -NoNewline } }
193. Play a beep sound - [Console]::Beep(500, 1000)
194. Get clipboard content - Get-Clipboard
195. Set clipboard content - 'Hello' | Set-Clipboard
196. Generate QR code (requires module) - Install-Module -Name QRCodeGenerator; New-QRCode -Content 'https://example.com'
197. Display a progress bar - 1..100 | ForEach-Object { Write-Progress -Activity 'Processing' -Status "$_%" -PercentComplete $_; Start-Sleep -Milliseconds 50 }
198. Display rainbow text - 'Hello' | ForEach-Object { $i=0; [char[]]$_ | ForEach-Object { Write-Host $_ -ForegroundColor ($i++ % 15) -NoNewline } }
199. Play a tune (beeps) - 500,300,400,200 | ForEach-Object { [Console]::Beep($_, 200) }
200. Get weather (simple) - (Invoke-RestMethod "wttr.in?format=3").Trim()
201. Simulate typing - 'Hello' | ForEach-Object { $_.ToCharArray() | ForEach-Object { [Console]::Write($_); Start-Sleep -Milliseconds 100 } }
202. Get random quote - (Invoke-RestMethod 'https://api.quotable.io/random').content
203. List fonts - (New-Object System.Drawing.Text.InstalledFontCollection).Families
204. Flash console window - 
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
