# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
#Define a log-file to add to ossec
define wazuh::addlog (
  $logfile      = undef,
  $logtype      = 'syslog',
  $logcommand   = undef,
  $commandalias = undef,
  $frequency    = undef,
) {
  require wazuh::params_manager

  concat::fragment { "ossec.conf_localfile-${name}":
    target  => 'ossec.conf',
    content => template('wazuh/fragments/_localfile_generation.erb'),
    order   => 21,
  }

}
