
title 'EventLogs'

control 'logging' do
  impact 1.0
  title 'Advanced logging present'
  desc 'Ensure that necessary advanced logging is configured'
  describe powershell('Get-EventLog -List') do
    its('stdout') { should include 'Security' }
    its('stdout') { should include 'System' }
    its('stdout') { should include 'Windows PowerShell' }
  end
  describe powershell('Get-WinEvent -ListProvider *') do
    its('stdout') { should include 'Microsoft-Windows-AppLocker' }
    its('stdout') { should include 'Microsoft-Windows-Sysmon' }
    its('stdout') { should include 'Microsoft-Windows-TaskScheduler' }
  end
  describe powershell('Get-WinEvent -ListLog *') do
    its('stdout') { should include 'Microsoft-Windows-AppLocker/EXE and DLL' }
    its('stdout') { should include 'Microsoft-Windows-Sysmon/Operational' }
    its('stdout') { should include 'Microsoft-Windows-TaskScheduler/Operational' }
  end
  # osquery
end
