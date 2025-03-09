String Manipulation
Reverse a string: 'Hello' | ForEach-Object { $_.ToCharArray() } | ForEach-Object { $r = $_ + $r }; $r

Convert to uppercase: 'hello' | ForEach-Object { $_.ToUpper() }

Convert to lowercase: 'HELLO' | ForEach-Object { $_.ToLower() }

Count characters in a string: 'Hello World'.Length

Replace text in a string: 'Hello World' -replace 'World', 'PowerShell'

Split a string into array: 'a,b,c' -split ','

Join array into string: ('a', 'b', 'c') -join '-'

Trim whitespace: '  Hello  ' | ForEach-Object { $_.Trim() }

Extract substring: 'Hello World'.Substring(0,5)

Check if string contains text: 'Hello World' -like '*World*'

File and Directory Operations
List all files in directory: Get-ChildItem -Path C:\ -File

List all directories: Get-ChildItem -Path C:\ -Directory

Count files in a folder: (Get-ChildItem -Path C:\ -File).Count

Get file size (MB): (Get-Item -Path C:\file.txt).Length / 1MB

Delete files older than 30 days: Get-ChildItem -Path C:\ -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item

Rename all files in folder: Get-ChildItem -Path C:\ -File | Rename-Item -NewName { $_.Name -replace 'old', 'new' }

Create a new file: New-Item -Path C:\newfile.txt -ItemType File

Create a new directory: New-Item -Path C:\newfolder -ItemType Directory

Read file content: Get-Content -Path C:\file.txt

Write to a file: 'Hello' | Out-File -FilePath C:\file.txt

System Information
Get OS version: (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

Get CPU info: Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores

Get total RAM (GB): (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB

Get free disk space (GB): (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB

List all running processes: Get-Process

Get process CPU usage: Get-Process | Sort-Object CPU -Descending | Select-Object -First 5

Check uptime: (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

Get installed software: Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version

List all services: Get-Service

Get running services: Get-Service | Where-Object { $_.Status -eq 'Running' }

Network Utilities
Get IP address: (Get-NetIPAddress -AddressFamily IPv4).IPAddress

Test network connection: Test-Connection -ComputerName google.com -Count 4

Get DNS servers: (Get-DnsClientServerAddress).ServerAddresses

Flush DNS cache: Clear-DnsClientCache

Get open ports: Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }

Resolve hostname to IP: [System.Net.Dns]::GetHostAddresses('google.com')

Get MAC address: (Get-NetAdapter).MacAddress

Check internet speed (simple ping): Measure-Command { Test-Connection -ComputerName google.com -Count 10 }

List network adapters: Get-NetAdapter

Disable a network adapter: Disable-NetAdapter -Name 'Ethernet' -Confirm:$false

Process and Task Management
Kill a process by name: Stop-Process -Name notepad -Force

Start a process: Start-Process -FilePath notepad.exe

Get process memory usage (MB): Get-Process | Select-Object Name, @{Name='MemoryMB';Expression={$_.WorkingSet/1MB}}

List processes by memory usage: Get-Process | Sort-Object WS -Descending | Select-Object -First 5

Restart a service: Restart-Service -Name spooler

Stop a service: Stop-Service -Name spooler -Force

Start a service: Start-Service -Name spooler

Get scheduled tasks: Get-ScheduledTask

Run a task now: Start-ScheduledTask -TaskName 'MyTask'

Disable a scheduled task: Disable-ScheduledTask -TaskName 'MyTask'

User and Security
Get current user: $env:USERNAME

List all local users: Get-LocalUser

Create a new local user: New-LocalUser -Name 'TestUser' -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)

Add user to admin group: Add-LocalGroupMember -Group 'Administrators' -Member 'TestUser'

Get logged-on users: query user

Lock the workstation: rundll32.exe user32.dll,LockWorkStation

Log off current user: logoff

Get password expiration date: (Get-LocalUser -Name $env:USERNAME).PasswordExpires

List group memberships: Get-LocalGroupMember -Group 'Administrators'

Check if running as admin: [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'

Date and Time
Get current date/time: Get-Date

Add days to current date: (Get-Date).AddDays(7)

Format date as YYYY-MM-DD: Get-Date -Format 'yyyy-MM-dd'

Get timestamp: (Get-Date).ToFileTime()

Convert Unix timestamp to date: [DateTimeOffset]::FromUnixTimeSeconds(1640995200).DateTime

Get day of the week: (Get-Date).DayOfWeek

Set system time: Set-Date -Date '2025-03-08 12:00:00'

Get time zone: (Get-TimeZone).Id

Calculate time difference: (Get-Date) - (Get-Date '2025-01-01')

Get elapsed time of command: Measure-Command { Start-Sleep -Seconds 2 }

Miscellaneous Utilities
Generate random number: Get-Random -Minimum 1 -Maximum 100

Generate random password: -join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})

Convert to JSON: @{Name='Test';Value=123} | ConvertTo-Json

Convert from JSON: '{"Name":"Test","Value":123}' | ConvertFrom-Json

Base64 encode: [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('Hello'))

Base64 decode: [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8='))

Calculate hash (SHA256): (Get-FileHash -Path C:\file.txt -Algorithm SHA256).Hash

Compress a folder: Compress-Archive -Path C:\folder -DestinationPath C:\archive.zip

Extract a zip file: Expand-Archive -Path C:\archive.zip -DestinationPath C:\folder

Speak text aloud: Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('Hello')

System Maintenance
Clear recycle bin: Clear-RecycleBin -Force

Get event logs (errors): Get-EventLog -LogName System -EntryType Error -Newest 10

Restart computer: Restart-Computer -Force

Shutdown computer: Stop-Computer -Force

Check disk health: Get-Disk | Select-Object Number, FriendlyName, HealthStatus

Repair disk errors: Repair-Volume -DriveLetter C -Scan

Defragment drive: Optimize-Volume -DriveLetter C

Get Windows updates: Get-WindowsUpdate

Install all updates: Install-WindowsUpdate -AcceptAll

Clear temp files: Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

Fun and Cool Tricks
Display ASCII art: 'Hello' | ForEach-Object { [char[]]$_ | ForEach-Object { Write-Host $_ -NoNewline } }

Play a beep sound: [Console]::Beep(500, 1000)

Get clipboard content: Get-Clipboard

Set clipboard content: 'Hello' | Set-Clipboard

Generate QR code (requires module): Install-Module -Name QRCodeGenerator; New-QRCode -Content 'https://example.com'

Count words in text: ('Hello world' -split '\s+').Count

Reverse array: $a = 1,2,3; [array]::Reverse($a); $a

Sort array: $a = 3,1,2; $a | Sort-Object

Get public IP: (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json').ip

1..100 | ForEach-Object { Write-Progress -Activity 'Processing' -Status "$_%" -PercentComplete $_; Start-Sleep -Milliseconds 50 }

String and Data Manipulation
Capitalize first letter: 'hello' | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }

Remove duplicates from array: $a = 1,2,2,3; $a | Sort-Object -Unique

Pad string with zeros: '42' | ForEach-Object { $_.PadLeft(5, '0') }

Extract numbers from string: 'abc123def' -replace '[^\d]'

Count vowels in string: ('hello' -split '' | Where-Object { $_ -match '[aeiou]' }).Count

Reverse words in sentence: ('Hello World' -split ' ' | ForEach-Object { $r = $_ + ' ' + $r }; $r.Trim())

Generate GUID: [Guid]::NewGuid().ToString()

Check if string is palindrome: $s = 'radar'; $s -eq ($s[-1..-($s.Length)] -join '')

Convert string to ASCII values: 'Hello' | ForEach-Object { [int[]][char[]]$_ }

Mask string (e.g., password): 'password' | ForEach-Object { '*' * $_.Length }

File and Directory Operations
List hidden files: Get-ChildItem -Path C:\ -Hidden -File

Get largest file in folder: Get-ChildItem -Path C:\ -File | Sort-Object Length -Descending | Select-Object -First 1

Copy files modified today: Get-ChildItem -Path C:\ | Where-Object { $_.LastWriteTime -gt (Get-Date).Date } | Copy-Item -Destination D:\

Find duplicate files by hash: Get-ChildItem -Path C:\ -File | Group-Object { (Get-FileHash $_.FullName).Hash } | Where-Object { $_.Count -gt 1 }

Move files by extension: Get-ChildItem -Path C:\ *.txt | Move-Item -Destination C:\TextFiles

Get folder size (MB): (Get-ChildItem -Path C:\ -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB

List empty folders: Get-ChildItem -Path C:\ -Directory | Where-Object { (Get-ChildItem $_.FullName) -eq $null }

Append text to file: 'New line' | Add-Content -Path C:\file.txt

Search file content: Select-String -Path C:\*.txt -Pattern 'error'

Backup a folder: Copy-Item -Path C:\folder -Destination "C:\backup_$(Get-Date -Format 'yyyyMMdd')" -Recurse

System Information
Get motherboard info: Get-CimInstance -ClassName Win32_BaseBoard | Select-Object Manufacturer, Product

List USB devices: Get-CimInstance -ClassName Win32_USBControllerDevice | ForEach-Object { [wmi]$_.Dependent }

Get GPU info: Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterRAM

Check battery status: (Get-CimInstance -ClassName Win32_Battery).BatteryStatus

Get system boot time: (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

List environment variables: Get-ChildItem Env:

Get CPU temperature (if supported): Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature

Get BIOS version: (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion

List hotfixes: Get-HotFix | Select-Object HotFixID, InstalledOn

Get system serial number: (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

Network Utilities
Get default gateway: (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop

List active connections: Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }

Get network usage (bytes sent): (Get-NetAdapterStatistics).SentBytes

Enable DHCP on adapter: Set-NetIPInterface -InterfaceAlias 'Ethernet' -Dhcp Enabled

Set static IP: New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress '192.168.1.100' -PrefixLength 24 -DefaultGateway '192.168.1.1'

Restart network adapter: Restart-NetAdapter -Name 'Ethernet'

Get Wi-Fi profiles: netsh wlan show profiles

Export Wi-Fi profile: netsh wlan export profile name='MyWiFi' folder=C:\

Get proxy settings: (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer

Trace route: Test-NetConnection -ComputerName google.com -TraceRoute

Process and Task Management
Kill processes over 1GB memory: Get-Process | Where-Object { $_.WS -gt 1GB } | Stop-Process -Force

List processes by company: Get-Process | Group-Object Company

Get process start time: (Get-Process -Name notepad).StartTime

Run command as another user: Start-Process -FilePath cmd.exe -Credential (Get-Credential)

Get service dependencies: Get-Service -Name spooler -RequiredServices

List services by start type: Get-Service | Group-Object StartType

Create scheduled task (daily): Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'notepad') -Trigger (New-ScheduledTaskTrigger -Daily -At '9AM') -TaskName 'DailyNote'

Export scheduled tasks: Get-ScheduledTask | Export-ScheduledTask

Get process path: (Get-Process -Name notepad).Path

Monitor process start: Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action { Write-Host "$($event.SourceEventArgs.NewEvent.ProcessName) started" }

User and Security
List all groups: Get-LocalGroup

Remove user from group: Remove-LocalGroupMember -Group 'Administrators' -Member 'TestUser'

Get SID of current user: [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Enable guest account: Enable-LocalUser -Name 'Guest'

Disable UAC (requires restart): Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0

Get firewall rules: Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }

Block IP in firewall: New-NetFirewallRule -Name 'BlockIP' -Direction Inbound -Action Block -RemoteAddress '192.168.1.100'

Get BitLocker status: (Get-BitLockerVolume -MountPoint C:).ProtectionStatus

List shadow copies: Get-CimInstance -ClassName Win32_ShadowCopy

Create shadow copy: wmic shadowcopy create Volume=C:\

Date and Time
Get UTC time: (Get-Date).ToUniversalTime()

Subtract hours: (Get-Date).AddHours(-3)

Get first day of month: (Get-Date -Day 1).Date

Get last day of month: (Get-Date -Day 1).AddMonths(1).AddDays(-1).Date

Convert to epoch seconds: [int64]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds

Get week number: (Get-Date).DayOfYear / 7 -as [int]

Set time zone: Set-TimeZone -Id 'Pacific Standard Time'

Compare dates: (Get-Date '2025-01-01') -gt (Get-Date)

Get sunrise/sunset (approx): Invoke-RestMethod "https://api.sunrise-sunset.org/json?lat=40&lng=-74" | Select-Object -Property sunrise, sunset

Log time to file: Get-Date | Out-File -FilePath C:\log.txt -Append

Miscellaneous Utilities
Generate random color hex: '#{0:X6}' -f (Get-Random -Minimum 0 -Maximum 16777215)

Convert CSV to object: Import-Csv -Path C:\data.csv

Export to CSV: Get-Process | Export-Csv -Path C:\processes.csv -NoTypeInformation

Encrypt a file: Protect-CmsMessage -To '*self*' -Content (Get-Content C:\file.txt -Raw) | Out-File C:\encrypted.txt

Decrypt a file: Unprotect-CmsMessage -Path C:\encrypted.txt | Out-File C:\decrypted.txt

Generate lorem ipsum: -join ((65..90) | Get-Random -Count 50 | ForEach-Object { [char]$_ })

Count lines in file: (Get-Content -Path C:\file.txt).Count

Convert to binary: [Convert]::ToString(42, 2)

Convert from binary: [Convert]::ToInt32('101010', 2)

Check PowerShell version: $PSVersionTable.PSVersion

System Maintenance
Get pending reboots: (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').RebootRequired

List installed drivers: Get-WindowsDriver -Online

Uninstall software: Get-CimInstance -ClassName Win32_Product -Filter "Name='AppName'" | Invoke-CimMethod -MethodName Uninstall

Clear event log: Clear-EventLog -LogName Application

Get system uptime in days: ((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).Days

Check memory usage %: 100 * (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory

List startup programs: Get-CimInstance -ClassName Win32_StartupCommand

Disable startup program: Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ProgramName'

Get disk SMART status: (Get-Disk).OperationalStatus

Run disk cleanup: cleanmgr /sagerun:1

Fun and Cool Tricks
Display rainbow text: 'Hello' | ForEach-Object { $i=0; [char[]]$_ | ForEach-Object { Write-Host $_ -ForegroundColor ($i++ % 15) -NoNewline } }

Play a tune (beeps): 500,300,400,200 | ForEach-Object { [Console]::Beep($_, 200) }

Get weather (simple): (Invoke-RestMethod "wttr.in?format=3").Trim()

Reverse file content: (Get-Content C:\file.txt) | ForEach-Object { $r = $_ + $r }; $r | Out-File C:\reversed.txt

Simulate typing: 'Hello' | ForEach-Object { [Console]::Write($_); Start-Sleep -Milliseconds 100 }

Get random quote: (Invoke-RestMethod 'https://api.quotable.io/random').content

Create shortcut: New-Item -ItemType SymbolicLink -Path C:\link -Target C:\target

List fonts: (New-Object System.Drawing.Text.InstalledFontCollection).Families

Get screen resolution: (Get-CimInstance -ClassName Win32_VideoController).CurrentHorizontalResolution

Flash console window: 1..5 | ForEach-Object { [Console]::Beep(800, 100); Start-Sleep -Milliseconds 200 }


