# Copyright (C) 2015, Wazuh Inc.
#Define a log-file to add to ossec
define wazuh::addlog (
  $logfile      = undef,
  $logtype      = 'syslog',
  $logcommand   = undef,
  $commandalias = undef,
  $frequency    = undef,
  $target_arg   = 'manager_ossec.conf',
) {
  require wazuh::params_manager

  concat::fragment { "ossec.conf_localfile-${logfile}":
    target  => $target_arg,
    content => template('wazuh/fragments/_localfile_generation.erb'),
    order   => 21,
  }
}
