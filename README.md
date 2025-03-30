Windows Program Management
1. Lists installed programs with details - Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
Process and DLL Monitoring
2. Find processes using a specific DLL - ps | where { $_.Modules.modulename -ieq 'netapi32.dll' }
3. 
4. Keyboard Automation
5. Toggle Caps Lock 10 times with 200ms delay - $wshell = New-Object -ComObject WScript.Shell; 1..10 | ForEach-Object { $wshell.SendKeys("{CAPSLOCK}") ; Start-Sleep -Milliseconds 200 }
String and Data Manipulation
6. Reverse a string - 'Hello' | ForEach-Object { $_.ToCharArray() } | ForEach-Object { $r = $_ + $r }; $r
7. Convert to uppercase - 'hello' | ForEach-Object { $_.ToUpper() }
8. Convert to lowercase - 'HELLO' | ForEach-Object { $_.ToLower() }
9. Count characters in a string - 'Hello World'.Length
10. Replace text in a string - 'Hello World' -replace 'World', 'PowerShell'
11. Split a string into array - 'a,b,c' -split ','
12. Join array into string - ('a', 'b', 'c') -join '-'
13. Trim whitespace - ' Hello ' | ForEach-Object { $_.Trim() }
14. Extract substring - 'Hello World'.Substring(0,5)
15. Check if string contains text - 'Hello World' -like '*World*'
16. Capitalize first letter - 'hello' | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }
17. Remove duplicates from array - $a = 1,2,2,3; $a | Sort-Object -Unique
18. Pad string with zeros - '42' | ForEach-Object { $_.PadLeft(5, '0') }
19. Extract numbers from string - 'abc123def' -replace '[^\d]'
20. Count vowels in string - ('hello' -split '' | Where-Object { $_ -match '[aeiou]' }).Count
21. Reverse words in sentence - ('Hello World' -split ' ' | ForEach-Object { $r = $_ + ' ' + $r }; $r.Trim())
22. Generate GUID - [Guid]::NewGuid().ToString()
23. Check if string is palindrome - $s = 'radar'; $s -eq ($s[-1..-($s.Length)] -join '')
24. Convert string to ASCII values - 'Hello' | ForEach-Object { [int[]][char[]]$_ }
25. Mask string (e.g., password) - 'password' | ForEach-Object { '*' * $_.Length }
26. Reverse array - $a = 1,2,3; [array]::Reverse($a); $a
27. Sort array - $a = 3,1,2; $a | Sort-Object
28. Count words in text - ('Hello world' -split '\s+').Count
29. Convert to binary - [Convert]::ToString(42, 2)
30. Convert from binary - [Convert]::ToInt32('101010', 2)
File and Directory Operations
31. List all files in directory - Get-ChildItem -Path C:\ -File
32. List all directories - Get-ChildItem -Path C:\ -Directory
33. Count files in a folder - (Get-ChildItem -Path C:\ -File).Count
34. Get file size (MB) - (Get-Item -Path C:\file.txt).Length / 1MB
35. Delete files older than 30 days - Get-ChildItem -Path C:\ -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item
36. Rename all files in folder - Get-ChildItem -Path C:\ -File | Rename-Item -NewName { $_.Name -replace 'old', 'new' }
37. Create a new file - New-Item -Path C:\newfile.txt -ItemType File
38. Create a new directory - New-Item -Path C:\newfolder -ItemType Directory
39. Read file content - Get-Content -Path C:\file.txt
40. Write to a file - 'Hello' | Out-File -FilePath C:\file.txt
41. List hidden files - Get-ChildItem -Path C:\ -Hidden -File
42. Get largest file in folder - Get-ChildItem -Path C:\ -File | Sort-Object Length -Descending | Select-Object -First 1
43. Copy files modified today - Get-ChildItem -Path C:\ | Where-Object { $_.LastWriteTime -gt (Get-Date).Date } | Copy-Item -Destination D:\
44. Find duplicate files by hash - Get-ChildItem -Path C:\ -File | Group-Object { (Get-FileHash $_.FullName).Hash } | Where-Object { $_.Count -gt 1 }
45. Move files by extension - Get-ChildItem -Path C:\ *.txt | Move-Item -Destination C:\TextFiles
46. Get folder size (MB) - (Get-ChildItem -Path C:\ -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
47. List empty folders - Get-ChildItem -Path C:\ -Directory | Where-Object { (Get-ChildItem $_.FullName) -eq $null }
48. Append text to file - 'New line' | Add-Content -Path C:\file.txt
49. Search file content - Select-String -Path C:\*.txt -Pattern 'error'
50. Backup a folder - Copy-Item -Path C:\folder -Destination "C:\backup_$(Get-Date -Format 'yyyyMMdd')" -Recurse
51. Compress a folder - Compress-Archive -Path C:\folder -DestinationPath C:\archive.zip
52. Extract a zip file - Expand-Archive -Path C:\archive.zip -DestinationPath C:\folder
53. Count lines in file - (Get-Content -Path C:\file.txt).Count
54. Reverse file content - (Get-Content C:\file.txt) | ForEach-Object { $r = $_ + $r }; $r | Out-File C:\reversed.txt
System Information
55. Get OS version - (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
56. Get CPU info - Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores
57. Get total RAM (GB) - (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB
58. Get free disk space (GB) - (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
59. Check uptime - (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
60. Get installed software - Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version
61. Get motherboard info - Get-CimInstance -ClassName Win32_BaseBoard | Select-Object Manufacturer, Product
62. List USB devices - Get-CimInstance -ClassName Win32_USBControllerDevice | ForEach-Object { [wmi]$_.Dependent }
63. Get GPU info - Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterRAM
64. Check battery status - (Get-CimInstance -ClassName Win32_Battery).BatteryStatus
65. Get system boot time - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
66. List environment variables - Get-ChildItem Env:
67. Get CPU temperature (if supported) - Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature
68. Get BIOS version - (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
69. List hotfixes - Get-HotFix | Select-Object HotFixID, InstalledOn
70. Get system serial number - (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
71. Check PowerShell version - $PSVersionTable.PSVersion
72. Get screen resolution - (Get-CimInstance -ClassName Win32_VideoController).CurrentHorizontalResolution
Network Utilities
73. Get IP address - (Get-NetIPAddress -AddressFamily IPv4).IPAddress
74. Test network connection - Test-Connection -ComputerName google.com -Count 4
75. Get DNS servers - (Get-DnsClientServerAddress).ServerAddresses
76. Flush DNS cache - Clear-DnsClientCache
77. Get open ports - Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
78. Resolve hostname to IP - [System.Net.Dns]::GetHostAddresses('google.com')
79. Get MAC address - (Get-NetAdapter).MacAddress
80. Check internet speed (simple ping) - Measure-Command { Test-Connection -ComputerName google.com -Count 10 }
81. List network adapters - Get-NetAdapter
82. Disable a network adapter - Disable-NetAdapter -Name 'Ethernet' -Confirm:$false
83. Get default gateway - (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop
84. List active connections - Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
85. Get network usage (bytes sent) - (Get-NetAdapterStatistics).SentBytes
86. Enable DHCP on adapter - Set-NetIPInterface -InterfaceAlias 'Ethernet' -Dhcp Enabled
87. Set static IP - New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress '192.168.1.100' -PrefixLength 24 -DefaultGateway '192.168.1.1'
88. Restart network adapter - Restart-NetAdapter -Name 'Ethernet'
89. Get Wi-Fi profiles - netsh wlan show profiles
90. Export Wi-Fi profile - netsh wlan export profile name='MyWiFi' folder=C:\
91. Get proxy settings - (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
92. Trace route - Test-NetConnection -ComputerName google.com -TraceRoute
93. Get public IP - (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json').ip
Process and Task Management
94. List all running processes - Get-Process
95. Get process CPU usage - Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
96. Kill a process by name - Stop-Process -Name notepad -Force
97. Start a process - Start-Process -FilePath notepad.exe
98. Get process memory usage (MB) - Get-Process | Select-Object Name, @{Name='MemoryMB';Expression={$_.WorkingSet/1MB}}
99. List processes by memory usage - Get-Process | Sort-Object WS -Descending | Select-Object -First 5
100. Restart a service - Restart-Service -Name spooler
101. Stop a service - Stop-Service -Name spooler -Force
102. Start a service - Start-Service -Name spooler
103. Get scheduled tasks - Get-ScheduledTask
104. Run a task now - Start-ScheduledTask -TaskName 'MyTask'
105. Disable a scheduled task - Disable-ScheduledTask -TaskName 'MyTask'
106. Kill processes over 1GB memory - Get-Process | Where-Object { $_.WS -gt 1GB } | Stop-Process -Force
107. List processes by company - Get-Process | Group-Object Company
108. Get process start time - (Get-Process -Name notepad).StartTime
109. Run command as another user - Start-Process -FilePath cmd.exe -Credential (Get-Credential)
110. Get service dependencies - Get-Service -Name spooler -RequiredServices
111. List services by start type - Get-Service | Group-Object StartType
112. Create scheduled task (daily) - Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'notepad') -Trigger (New-ScheduledTaskTrigger -Daily -At '9AM') -TaskName 'DailyNote'
113. Export scheduled tasks - Get-ScheduledTask | Export-ScheduledTask
114. Get process path - (Get-Process -Name notepad).Path
115. Monitor process start - Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action { Write-Host "$($event.SourceEventArgs.NewEvent.ProcessName) started" }
116. List all services - Get-Service
117. Get running services - Get-Service | Where-Object { $_.Status -eq 'Running' }
User and Security
118. Get current user - $env:USERNAME
119. List all local users - Get-LocalUser
120. Create a new local user - New-LocalUser -Name 'TestUser' -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
121. Add user to admin group - Add-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
122. Get logged-on users - query user
123. Lock the workstation - rundll32.exe user32.dll,LockWorkStation
124. Log off current user - logoff
125. Get password expiration date - (Get-LocalUser -Name $env:USERNAME).PasswordExpires
126. List group memberships - Get-LocalGroupMember -Group 'Administrators'
127. Check if running as admin - [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'
128. List all groups - Get-LocalGroup
129. Remove user from group - Remove-LocalGroupMember -Group 'Administrators' -Member 'TestUser'
130. Get SID of current user - [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
131. Enable guest account - Enable-LocalUser -Name 'Guest'
132. Disable UAC (requires restart) - Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0
133. Get firewall rules - Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
134. Block IP in firewall - New-NetFirewallRule -Name 'BlockIP' -Direction Inbound -Action Block -RemoteAddress '192.168.1.100'
135. Get BitLocker status - (Get-BitLockerVolume -MountPoint C:).ProtectionStatus
136. List shadow copies - Get-CimInstance -ClassName Win32_ShadowCopy
137. Create shadow copy - wmic shadowcopy create Volume=C:\
Date and Time
138. Get current date/time - Get-Date
139. Add days to current date - (Get-Date).AddDays(7)
140. Format date as YYYY-MM-DD - Get-Date -Format 'yyyy-MM-dd'
141. Get timestamp - (Get-Date).ToFileTime()
142. Convert Unix timestamp to date - [DateTimeOffset]::FromUnixTimeSeconds(1640995200).DateTime
143. Get day of the week - (Get-Date).DayOfWeek
144. Set system time - Set-Date -Date '2025-03-08 12:00:00'
145. Get time zone - (Get-TimeZone).Id
146. Calculate time difference - (Get-Date) - (Get-Date '2025-01-01')
147. Get elapsed time of command - Measure-Command { Start-Sleep -Seconds 2 }
148. Get UTC time - (Get-Date).ToUniversalTime()
149. Subtract hours - (Get-Date).AddHours(-3)
150. Get first day of month - (Get-Date -Day 1).Date
151. Get last day of month - (Get-Date -Day 1).AddMonths(1).AddDays(-1).Date
152. Convert to epoch seconds - [int64]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
153. Get week number - (Get-Date).DayOfYear / 7 -as [int]
154. Set time zone - Set-TimeZone -Id 'Pacific Standard Time'
155. Compare dates - (Get-Date '2025-01-01') -gt (Get-Date)
156. Get sunrise/sunset (approx) - Invoke-RestMethod "https://api.sunrise-sunset.org/json?lat=40&lng=-74" | Select-Object -Property sunrise, sunset
157. Log time to file - Get-Date | Out-File -FilePath C:\log.txt -Append
Miscellaneous Utilities
158. Generate random number - Get-Random -Minimum 1 -Maximum 100
159. Generate random password - -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})
160. Convert to JSON - @{Name='Test';Value=123} | ConvertTo-Json
161. Convert from JSON - '{"Name":"Test","Value":123}' | ConvertFrom-Json
162. Base64 encode - [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Hello'))
163. Base64 decode - [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8='))
164. Calculate hash (SHA256) - (Get-FileHash -Path C:\file.txt -Algorithm SHA256).Hash
165. Speak text aloud - Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Hello')
166. Generate random color hex - '#{0:X6}' -f (Get-Random -Minimum 0 -Maximum 16777215)
167. Convert CSV to object - Import-Csv -Path C:\data.csv
168. Export to CSV - Get-Process | Export-Csv -Path C:\processes.csv -NoTypeInformation
169. Encrypt a file - Protect-CmsMessage -To '*self*' -Content (Get-Content C:\file.txt -Raw) | Out-File C:\encrypted.txt
170. Decrypt a file - Unprotect-CmsMessage -Path C:\encrypted.txt | Out-File C:\decrypted.txt
171. Generate lorem ipsum - -join ((65..90) | Get-Random -Count 50 | ForEach-Object { [char]$_ })
172. Create shortcut - New-Item -ItemType SymbolicLink -Path C:\link -Target C:\target
System Maintenance
173. Clear recycle bin - Clear-RecycleBin -Force
174. Get event logs (errors) - Get-EventLog -LogName System -EntryType Error -Newest 10
175. Restart computer - Restart-Computer -Force
176. Shutdown computer - Stop-Computer -Force
177. Check disk health - Get-Disk | Select-Object Number, FriendlyName, HealthStatus
178. Repair disk errors - Repair-Volume -DriveLetter C -Scan
179. Defragment drive - Optimize-Volume -DriveLetter C
180. Get Windows updates - Get-WindowsUpdate
181. Install all updates - Install-WindowsUpdate -AcceptAll
182. Clear temp files - Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
183. Get pending reboots - (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').RebootRequired
184. List installed drivers - Get-WindowsDriver -Online
185. Uninstall software - Get-CimInstance -ClassName Win32_Product -Filter "Name='AppName'" | Invoke-CimMethod -MethodName Uninstall
186. Clear event log - Clear-EventLog -LogName Application
187. Get system uptime in days - ((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).Days
188. Check memory usage % - 100 * (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
189. List startup programs - Get-CimInstance -ClassName Win32_StartupCommand
190. Disable startup program - Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ProgramName'
191. Get disk SMART status - (Get-Disk).OperationalStatus
192. Run disk cleanup - cleanmgr /sagerun:1
Fun and Cool Tricks
193. Display ASCII art - 'Hello' | ForEach-Object { [char[]]$_ | ForEach-Object { Write-Host $_ -NoNewline } }
194. Play a beep sound - [Console]::Beep(500, 1000)
195. Get clipboard content - Get-Clipboard
196. Set clipboard content - 'Hello' | Set-Clipboard
197. Generate QR code (requires module) - Install-Module -Name QRCodeGenerator; New-QRCode -Content 'https://example.com'
198. Display a progress bar - 1..100 | ForEach-Object { Write-Progress -Activity 'Processing' -Status "$_%" -PercentComplete $_; Start-Sleep -Milliseconds 50 }
199. Display rainbow text - 'Hello' | ForEach-Object { $i=0; [char[]]$_ | ForEach-Object { Write-Host $_ -ForegroundColor ($i++ % 15) -NoNewline } }
200. Play a tune (beeps) - 500,300,400,200 | ForEach-Object { [Console]::Beep($_, 200) }
201. Get weather (simple) - (Invoke-RestMethod "wttr.in?format=3").Trim()
202. Simulate typing - 'Hello' | ForEach-Object { $_.ToCharArray() | ForEach-Object { [Console]::Write($_); Start-Sleep -Milliseconds 100 } }
203. Get random quote - (Invoke-RestMethod 'https://api.quotable.io/random').content
204. List fonts - (New-Object System.Drawing.Text.InstalledFontCollection).Families
205. Flash console window - 
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
