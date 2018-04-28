
do_aptsimulator_collection = attribute('do_aptsimulator_collection', default: false, description: 'Test APTSimulator collection detections')

if do_aptsimulator_collection
  title 'APTSimulator collection'

  control 'evasion-logging-processcmdline' do
    impact 1.0
    title 'Detection with ProcessCmdLine'
    desc 'Verify that cli tools activity is logged with EnableProcessCmdLine'
    #describe powershell("Get-Eventlog -LogName security | where {$_.eventID -eq 4688} | Format-Table TimeCreate,Message -wrap") do
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Security';Id=4688} | Format-Table Message -wrap") do
      its('stdout') { should include 'mkdir.exe' }
      its('stdout') { should include 'ping.exe' }
      its('stdout') { should include '7zip.exe' }
    end
  end

  control 'evasion-logging-sysmon' do
    impact 1.0
    title 'Detection with Sysmon'
    desc 'Verify that cli tools activity is logged with Sysinternals Sysmon'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-Sysmon/Operational';Id=1} | Format-Table Message -wrap") do
      its('stdout') { should include 'mkdir.exe' }
      its('stdout') { should include 'ping.exe' }
      its('stdout') { should include '7zip.exe' }
    end
  end

  control 'evasion-logging-applocker' do
    impact 1.0
    title 'Detection with Applocker'
    desc 'Verify that cli tools activity is logged with Applocker'
    describe powershell("Get-WinEvent -FilterHashTable @{logname='Microsoft-Windows-AppLocker/EXE and DLL';Id=8002} | Format-Table Message -wrap") do
      its('stdout') { should match /mkdir.exe was allowed to run/i }
      its('stdout') { should match /ping.exe/i }
      its('stdout') { should match /7zip.exe/i }
    end
  end

  control 'evasion-logging-osquery' do
    impact 1.0
    title 'Defense Evasion detection with osquery'
    desc 'Verify that activity is identified with osquery'
    describe file('c:\ProgramData\osquery\log\osqueryd.results.log') do
      its('stdout') { should match /mkdir.exe/i }
      its('stdout') { should match /ping.exe/i }
      its('stdout') { should match /7zip.exe/i }
    end
  end

end
