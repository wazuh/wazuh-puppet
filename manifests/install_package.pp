# Defined type to install Wazuh components from custom URLs
# @param package_name Name of the Wazuh component (e.g., 'wazuh-manager')
# @param wazuh_version Version of the component to install (e.g., '4.9.2')
define wazuh::install_package (
  $package_name   = undef,
  $wazuh_version  = '5.0.0'
) {
  case $facts['kernel'] {
    'Linux': {
      $download_path = '/tmp'
      $package_list_path = '/tmp/packages_url.txt'
      # Determine package provider based on OS family
      $provider = $facts['os']['family'] ? {
        'Debian' => 'dpkg',  # Correct provider name for .deb packages
        'RedHat' => 'rpm',   # Keep rpm for RedHat
        default  => fail("Unsupported OS family: ${facts['os']['family']}"),
      }

      # Determine package format (deb/rpm) based on OS family
      $compatibility = $facts['os']['family'] ? {
        'Debian' => 'deb',
        'RedHat' => 'rpm',
        default  => fail("Unsupported OS family: ${facts['os']['family']}"),
      }

      # Normalize architecture naming conventions
      $architecture = $facts['os']['architecture']

      # Generate package identifier package
      $package = "${package_name}_url_${architecture}_${compatibility}"

      # Download specific package using extracted URL
      exec { "download_${package}":
        command => "sh -c 'url=\$(grep -F '${package}:' /tmp/artifacts_url.txt | tr -d \"\\r\" | cut -d \" \" -f2); curl -o ${download_path}/${package} \"\$url\"'",
        unless  => "test -f ${download_path}/${package} && dpkg -I ${download_path}/${package} >/dev/null 2>&1",
        path    => ['/usr/bin', '/bin', '/sbin', '/usr/sbin'],
        timeout => 600,
      }

      # Install the package using correct provider
      package { "install_${package_name}":
        ensure   => installed,
        provider => $provider,  # Now using validated provider names
        source   => "/tmp/${package}",
        require  => Exec["download_${package}"],
      }
    }
    'windows': {
      $download_path = 'C:\\Temp'
      $package_msi_key = 'wazuh_agent_url_i386_msi'
      $package_list_path = 'C:/Windows/Temp/packages_url.txt'
      $msi_download_location = 'C:/Windows/Temp/wazuh-agent-installer.msi'
      $install_options = ['/qn']
      $cleanup_msi = true

      file { $download_path:
        ensure => directory,
      }

      exec { "extract_url${package_msi_key}":
        command   => "powershell -NoProfile -Command \"(Get-Content ${$package_list_path}) | `
                    Where-Object { \$_ -match '^${package_msi_key}:' } | `
                    ForEach-Object { (\$_ -split ':',2)[1].Trim() }\"",
        provider  => powershell,
        logoutput => true,
      }

      archive { 'download_msi_package':
        ensure  => present,
        path    => $msi_download_location,
        source  => $package_msi_url,
        extract => false,
        cleanup => false,
        before  => Package["install_${package_name}"],
      }

      package { "install_${package_name}":
        ensure          => installed,
        provider        => 'msi',
        source          => $msi_download_location,
        install_options => $install_options,
        require         => Archive['download_msi_package'],
      }

      if $cleanup_msi {
        file { 'remove_downloaded_msi':
          path    => $msi_download_location,
          ensure  => absent,
          require => Package[$package_name],
        }
      }
    }
    default: {
      fail("OS ${facts['os']['name']} is not supported")
    }
  }
}
