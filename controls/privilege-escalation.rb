
do_aptsimulator_privesc = attribute('do_aptsimulator_privesc', default: false, description: 'Test APTSimulator privilege escalation detections')

if do_aptsimulator_privesc
  title 'APTSimulator privilege-escalation'

end
