# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Define an email alert
define wazuh::email_alert(
  $alert_email,
  $alert_group = false,
  $target_arg  = 'manager_ossec.conf'
) {
  require wazuh::params_manager

  concat::fragment { $name:
    target  => $target_arg,
    order   => 66,
    content => template('wazuh/fragments/_email_alert.erb'),
  }
}
