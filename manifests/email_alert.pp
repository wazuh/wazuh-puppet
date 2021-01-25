# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Define an email alert
define wazuh::email_alert(
  $alert_email,
  $level = false,
  $alert_group = false,
  $event_location = false,
  $format = false,
  $rule_id = false,
  $do_not_delay = false,
  $do_not_group = false,
) {
  require wazuh::params_manager

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 66,
    content => template('wazuh/fragments/_email_alert.erb'),
  }
}
