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

Display a progress bar: 1..100 | ForEach-Object { Write-Progress -Activity 'Processing' -Status "$_%" -PercentComplete $_; Start-Sleep -Milliseconds 50 }

