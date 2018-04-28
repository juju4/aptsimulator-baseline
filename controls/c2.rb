
do_aptsimulator_c2 = attribute('do_aptsimulator_c2', default: false, description: 'Test APTSimulator C2 detections')

if do_aptsimulator_c2
  title 'APTSimulator command-and-control'

  # control group per log instead of test for performance reason
  control 'c2-logging-processcmdline' do
    impact 1.0
    title 'Detection with ProcessCmdLine'
    desc 'Verify that cli tools activity is logged with EnableProcessCmdLine'
    # describe powershell("Get-Eventlog -LogName security | where {$_.eventID -eq 4688} | Format-Table TimeCreate,Message -wrap") do
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Security';Id=4688} | Format-Table Message -wrap") do
      # C2 cli tools
      its('stdout') { should include 'curl.exe' }
      its('stdout') { should include 'nc.ps1' }
      its('stdout') { should include 'powercat' }
      its('stdout') { should include 'WMIBackdoor.ps1' }
    end
  end

  control 'c2-logging-sysmon' do
    impact 1.0
    title 'Detection with Sysmon'
    desc 'Verify that cli tools activity is logged with Sysinternals Sysmon'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';Id=1} | Format-Table Message -wrap") do
      its('stdout') { should include 'curl.exe' }
      its('stdout') { should include 'nc.ps1' }
      its('stdout') { should include 'powercat' }
      its('stdout') { should include 'WMIBackdoor.ps1' }
    end
  end

  # Powershell/Operational
  # New-WMIBackdoorTrigger

  control 'c2-logging-applocker' do
    impact 1.0
    title 'Detection with Applocker'
    desc 'Verify that cli tools activity is logged with Applocker'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';Id=8002} | Format-Table Message -wrap") do
      its('stdout') { should match /curl.exe was allowed to run/i }
    end
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/MSI and Script';Id=8002} | Format-Table Message -wrap") do
      its('stdout') { should match (/nc.ps1/i) }
      its('stdout') { should match (/WMIBackdoor.ps1/i) }
    end
  end

  control 'c2-logging-osquery' do
    impact 1.0
    title 'Detection with osquery'
    desc 'Verify that activity is identified with osquery'
    describe file('c:\ProgramData\osquery\log\osqueryd.results.log') do
      its('stdout') { should match (/curl.exe/i) }
      its('stdout') { should match (/nc.ps1/i) }
      its('stdout') { should match (/powercat/i) }
    end
  end

  control 'c2-logging-firewall' do
    impact 1.0
    title 'Detection with host firewall'
    desc 'Verify that activity is identied in local firewall log'
    describe file('c:\windows\system32\logfiles\firewall\pfirewall-public.log') do
      # raw.githubusercontent.com: github.map.fastly.net has address 151.101.124.133
      # its('content') { should match /151.101.124.133/ }
      its('content') { should match (/ALLOW 127.0.0.1 127.0.0.1/) }
    end
  end

  control 'c2-dns-cache' do
    impact 1.0
    title 'C2 DNS Cache traces'
    desc 'Verify that DNS activity is visible'
    describe command('ipconfig /displaydns') do
      its('stdout') { should cmp 'msupdater.com' }
      its('stdout') { should cmp 'twitterdocs.com' }
      its('stdout') { should cmp 'freenow.chickenkiller.com' }
      its('stdout') { should cmp 'www.googleaccountsservices.com' }
      its('stderr') { should eq '' }
      its('exit_status') { should eq 0 }
    end
  end

end
