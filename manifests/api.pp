#Setup for wazuh-api
class wazuh::api(
  $install_wazuh_api             = false,
  $api_config_params             = $::wazuh::params::api_config_params,
  $wazuh_api_enable_https        = false,
  $wazuh_api_server_crt          = undef,
  $wazuh_api_server_key          = undef,
  $api_service_provider          = $::wazuh::params::api_service_provider,
  $api_package_version           = 'installed',
  $manage_nodejs                 = true,
  $nodejs_repo_url_suffix        = '6.x',
  $api_config_template           = 'wazuh/api/config.js.erb',
  $wazuh_api_enable_behindproxy  = false,
) inherits wazuh::params {
  validate_bool(
    $install_wazuh_api
  )
  ### Wazuh API
  if $install_wazuh_api {
    validate_bool($manage_nodejs)
    if $manage_nodejs {
      validate_string($nodejs_repo_url_suffix)
      class { '::nodejs': repo_url_suffix => $nodejs_repo_url_suffix }
      Class['nodejs'] -> Package[$wazuh::params::api_package]
    }
  }
    package { $wazuh::params::api_package:
      ensure  => $api_package_version
    }
      file { '/var/ossec/api/configuration/config.js':
      content => template($api_config_template),
      owner   => 'root',
      group   => 'ossec',
      mode    => '0750',
      require => Package[$wazuh::params::api_package],
      notify  => Service[$wazuh::params::api_service],
    }

    service { $wazuh::params::api_service:
      ensure    => running,
      enable    => true,
      hasstatus => $wazuh::params::service_has_status,
      pattern   => $wazuh::params::api_service,
      provider  => $api_service_provider,
      require   => Package[$wazuh::params::api_package],
    }
}
