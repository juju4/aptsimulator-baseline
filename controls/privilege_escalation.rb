# frozen_string_literal: true

do_aptsimulator_privesc = input('do_aptsimulator_privesc', value: false, description: 'Test APTSimulator privilege escalation detections')

if do_aptsimulator_privesc
  title 'APTSimulator privilege-escalation'
  desc 'To be filled...'

end
