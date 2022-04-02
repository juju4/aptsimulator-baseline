# frozen_string_literal: true

do_aptsimulator_evasion = input('do_aptsimulator_evasion', value: true, description: 'Test APTSimulator defense evasion detections')

if do_aptsimulator_evasion
  title 'APTSimulator defense-evasion'

  # control group per log instead of test for performance reason
  control 'evasion-logging-processcmdline' do
    impact 1.0
    title 'Detection with ProcessCmdLine'
    desc 'Verify that cli tools activity is logged with EnableProcessCmdLine'
    # describe powershell("Get-Eventlog -LogName security | where {$_.eventID -eq 4688} | Format-Table TimeCreate,Message -wrap") do
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Security';Id=4688} | Format-Table Message -wrap") do
      # active-guest-acccount-admin
      its('stdout') { should include 'net.exe' }
      its('stdout') { should include ' guest ' }
      # fake svchost
      its('stdout') { should include 'svchost.exe' }
      # js dropper
      its('stdout') { should include 'regedit.exe' }
      its('stdout') { should include 'jsfix.reg' }
      its('stdout') { should include 'certutil.exe' }
      its('stdout') { should include 'wscript.exe' }
    end
  end

  control 'evasion-logging-sysmon' do
    impact 1.0
    title 'Detection with Sysmon'
    desc 'Verify that cli tools activity is logged with Sysinternals Sysmon'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';Id=1} | Format-Table Message -wrap") do
      its('stdout') { should include 'net.exe' }
      its('stdout') { should include ' guest ' }
      # fake svchost
      its('stdout') { should include 'svchost.exe' }
      # js dropper
      its('stdout') { should include 'regedit.exe' }
      its('stdout') { should include 'jsfix.reg' }
      its('stdout') { should include 'certutil.exe' }
      its('stdout') { should include 'wscript.exe' }
    end
  end

  control 'evasion-logging-applocker' do
    impact 1.0
    title 'Detection with Applocker'
    desc 'Verify that cli tools activity is logged with Applocker'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';Id=8002} | Format-Table Message -wrap") do
      its('stdout') { should match(/net.exe was allowed to run/i) }
      # fake svchost
      # its('stdout') { should match(/svchost.exe was allowed to run/i) }
      # js dropper
      its('stdout') { should match(/regedit.exe/i) }
      its('stdout') { should match(/certutil.exe/i) }
      its('stdout') { should match(/wscript.exe/i) }
    end
  end

  control 'evasion-logging-osquery' do
    impact 1.0
    title 'Defense Evasion detection with osquery'
    desc 'Verify that activity is identified with osquery'
    describe file('c:\ProgramData\osquery\log\osqueryd.results.log') do
      its('stdout') { should match(/net.exe/i) }
      # fake svchost
      its('stdout') { should match(/svchost.exe/i) }
      # js dropper
      its('stdout') { should match(/regedit.exe/i) }
      its('stdout') { should match(/certutil.exe/i) }
      its('stdout') { should match(/wscript.exe/i) }
    end
  end

  control 'evasion-logging-firewall' do
    impact 1.0
    title 'Defense Evasion detection with host firewall'
    desc 'Verify that activity is identied in local firewall log'
    describe file('c:\windows\system32\logfiles\firewall\pfirewall-public.log') do
      # raw.githubusercontent.com: github.map.fastly.net has address 151.101.124.133
      # its('content') { should match /151.101.124.133/ }
      its('content') { should match(/ALLOW ICMP 127.0.0.1 127.0.0.1/) }
    end
  end

  control 'evasion-etc-hosts' do
    impact 1.0
    title 'Defense Evasion etc hosts change'
    desc 'Verify that etc hosts changes are identified'
    describe file('c:\windows\system32\drivers\etc\hosts') do
      its('content') { should include 'update.microsoft.com' }
      its('content') { should include 'www.virustotal.com' }
      its('content') { should include 'www.www.com' }
      its('content') { should include 'dci.sophosupd.com' }
    end
  end
end
