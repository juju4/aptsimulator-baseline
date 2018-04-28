
do_aptsimulator_cred = attribute('do_aptsimulator_cred', default: false, description: 'Test APTSimulator cred detections')

if do_aptsimulator_cred
  title 'APTSimulator credential-access'

  control 'cred-procdump' do
    impact 1.0
    title 'Credentials procdump usage'
    desc 'Verify that cli tools activity is logged'
    describe powershell("Get-Eventlog -LogName security -include *procdump* | where {$_.eventID -eq 4688}") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-Eventlog -LogName security -include *lsass* | where {$_.eventID -eq 4688}") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -ProviderName Microsoft-Windows-AppLocker -include *procdump*") do
      its('stdout') { should_not eq '' }
    end
  end

  control 'cred-mimikatz' do
    impact 1.0
    title 'Credentials mimikatz usage'
    desc 'Verify that cli tools activity is logged'
    describe powershell("Get-Eventlog -LogName security -include *mim.exe* | where {$_.eventID -eq 4688}") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-WinEvent -ProviderName Microsoft-Windows-Powershell -include *Invoke-Mimikatz*") do
      its('stdout') { should_not eq '' }
    end
    # firewall log?
  end

  control 'cred-wce' do
    impact 1.0
    title 'Credentials WCE usage'
    desc 'Verify that cli tools activity is logged'
    describe powershell("Get-Eventlog -LogName security -include *eventcreate* | where {$_.eventID -eq 4688}") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-Eventlog -LogName system -include *WCESERVICE* | where {$_.eventID -eq 100}") do
      its('stdout') { should_not eq '' }
    end
    describe powershell("Get-Eventlog -LogName system -include *WCESERVICE* | where {$_.eventID -eq 101}") do
      its('stdout') { should_not eq '' }
    end
  end
end
