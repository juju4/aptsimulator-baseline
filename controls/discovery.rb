
do_aptsimulator_discovery = attribute('do_aptsimulator_discovery', default: false, description: 'Test APTSimulator discovery detections')

if do_aptsimulator_discovery
  title 'APTSimulator discovery'

  control 'discovery-nbtscan' do
    impact 1.0
    title 'Discovery cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *nbtscan.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match nbtscan.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL'} | where-object -Property Message -Match nbtscan.exe") do
      its('stdout') { should_not eq '' }
    end
    # osquery
  end

  control 'discovery-recon' do
    impact 1.0
    title 'Discovery recon cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *whoami* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell('Get-Eventlog -LogName security -include *systeminfo* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell('Get-Eventlog -LogName security -include *wmic* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match whoami.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property Image -Match wmic.exe") do
      its('stdout') { should include 'wmic qfe list full' }
      its('stdout') { should include 'wmic share get' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';id=8004} | where-object -Property Message -Match wmic.exe") do
      its('stdout') { should_not eq '' }
    end
    # osquery
  end

  control 'discovery-psexec' do
    impact 1.0
    title 'Discovery cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *p.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match p.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';id=8004} | where-object -Property Message -Match p.exe") do
      its('stdout') { should_not eq '' }
    end
    # osquery
  end

  control 'discovery-remote-exe' do
    impact 1.0
    title 'Discovery cli tools'
    desc 'Verify that cli tools activity is logged'
    describe powershell('Get-Eventlog -LogName security -include *xCmd.exe* | where {$_.eventID -eq 4688}') do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';id=1} | where-object -Property CommandLine -Match xCmd.exe") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';id=8004} | where-object -Property Message -Match xCmd.exe") do
      its('stdout') { should_not eq '' }
    end
    # osquery
  end
end
