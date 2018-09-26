# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Define an email alert
define wazuh::email_alert(
  $alert_email,
  $alert_group = false,
  Integer $alert_order = 65,
) {
  # Build email alert fragment
  concat::fragment { "ossec.conf_emailalert-${title}":
    target  => 'ossec.conf',
    order   => 65,
    content => template('wazuh/fragments/_email_alert.erb'),
  }
}
