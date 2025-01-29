# Defined type to install Wazuh components from custom URLs
# @param package_name Name of the Wazuh component (e.g., 'wazuh-manager')
# @param wazuh_version Version of the component to install (e.g., '4.9.2')
define wazuh::install_product (
  String $package_name,
  String $wazuh_version = '4.9.2',
) {

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
  $architecture = $facts['os']['architecture'] ? {
    'x86_64'  => 'amd64',   # Convert x86_64 to amd64
    'aarch64' => 'arm64',   # Convert aarch64 to arm64
    default   => $facts['os']['architecture'],
  }

  # Generate package identifier key
  $key = "${package_name}-${wazuh_version}-${architecture}.${compatibility}"

  # Download specific package using extracted URL
  exec { "download_${key}":
    command   => "url=$(grep -F \"${key}:\" /tmp/packages_url.txt | tr -d \"\\r\" | cut -d \" \" -f2); curl -sSf -o /tmp/${key} $url",
    unless    => "test -f /tmp/${key} && dpkg -I /tmp/${key} >/dev/null 2>&1",
    path      => ['/usr/bin', '/bin', '/sbin'],
    timeout   => 600,
    require   => [
      Exec['download_packages_url_from_url'],
    ],
  }

  # Install the package using correct provider
  package { $package_name:
    ensure   => installed,
    provider => $provider,  # Now using validated provider names
    source   => "/tmp/${key}",
    require  => Exec["download_${key}"],
  }
}
