[![Build Status](https://travis-ci.org/juju4/aptsimulator-baseline.svg?branch=master)](https://travis-ci.org/juju4/aptsimulator-baseline)

aptsimulator-baseline
================

This Baseline tests detection of APTSimulation

- https://github.com/juju4/aptsimulator-baseline

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/juju4/aptsimulator-baseline
$ inspec exec aptsimulator-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/juju4/aptsimulator-baseline

# run test on remote windows host on WinRM
$ inspec exec test.rb -t winrm://Administrator@windowshost --password 'your-password'
```

## FAQ

* windows event logs multiple extractions are very slow... be patient. As a result, only defense evasion testing is enabled by default. Always [prefer Get-WinEvent to Get-EventLog](https://4sysops.com/archives/fast-event-log-search-in-powershell-with-the-filterhashtable-parameter/)


## License

BSD 2-clause

