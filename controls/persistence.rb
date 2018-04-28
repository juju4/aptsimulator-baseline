
do_aptsimulator_persistence = attribute('do_aptsimulator_persistence', default: false, description: 'Test APTSimulator persistence detections')

if do_aptsimulator_persistence
  title 'APTSimulator persistence'

  control 'persistence-cli-at' do
    impact 1.0
    title 'Persistence cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *at.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match at.exe") do
      its('stdout') { should include 'mim.exe sekurlsa::LogonPasswords' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match sekurlsa") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-TaskScheduler/Operational';id=129} | where-object -Property CommandLine -Match mim.exe") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-reg-logging' do
    impact 1.0
    title 'Persistence registry'
    desc 'Verify that registry change is logged'
    describe powershell('Get-Eventlog -LogName security -include *p.exe* | where {$_.eventID -eq 4657}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match p.exe") do
      its('stdout') { should include 'reg add ' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=13} | where-object -Property Details -Match p.exe") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-cli-schtasks' do
    impact 1.0
    title 'Persistence cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *schtasks.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match schtasks.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match GameOver") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-TaskScheduler/Operational';id=129} | where-object -Property CommandLine -Match mim.exe") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-cli-schtasks-xml' do
    impact 1.0
    title 'Persistence cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match schtasks.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Powershell/Operational'} | where-object -Property CommandLine -Match schtasks-backdoor.ps1") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Powershell/Operational'} | where-object -Property Message -Match Invoke-Taskbackdoor") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-TaskScheduler/Operational';id=129} | where-object -Property Message -Match '8.8.8.8 -port 9999'") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-cli-sethc' do
    impact 1.0
    title 'Persistence cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *sethc.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match sethc.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell('Get-Eventlog -LogName security -include *sethc.exe* | where {$_.eventID -eq 4657}') do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-userinit' do
    impact 1.0
    title 'Persistence cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *sekurlsa::LogonPasswords* | where {$_.eventID -eq 4657}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1;Image='C:\Windows\System32\reg.exe'} | where-object -Property CommandLine -Match UserInitMprLogonScript") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'persistence-web-shells' do
    impact 1.0
    title 'Persistence web-shells'
  end

  control 'persistence-wmi' do
    impact 1.0
    title 'Persistence wmi'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match WMIBackdoor.ps1") do
      its('stdout') { should_not eq '' }
    end
    describe powershell('Get-WinEvent -ProviderName Microsoft-Windows-Powershell -include *WMIBackdoor.ps1*') do
      its('stdout') { should_not eq '' }
    end
  end
end
