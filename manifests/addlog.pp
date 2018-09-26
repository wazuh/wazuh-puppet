# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
#Define a log-file to add to ossec
define wazuh::addlog(
  String $logfile,
  String $friendly_name = undef,
  String $logtype       = 'syslog',
  Integer[0] $frequency = undef,
  $order                = 20,
) {
  # Friendly names are better because depending on the pattern passed
  #  in this could have unexpected results, but try to build a name 
  #  if not set
  if defined('$friendly_name') {
    $_fragment_name = $friendly_name
  } else {
    $_fragment_name = basename($logfile)
  }

  # Build log fragment
  concat::fragment { "ossec.conf_localfile-${_fragment_name}":
    target  => 'ossec.conf',
    content => template('wazuh/fragments/_localfile.erb'),
    order   => $order,
  }
}
