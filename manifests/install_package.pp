# Defined type to install Wazuh components from custom URLs
# @param package_name Name of the Wazuh component (e.g., 'wazuh-manager')
# @param wazuh_version Version of the component to install (e.g., '4.9.2')
define wazuh::install_package (
  String $package_name,
  String $wazuh_version = '5.0.0'
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

  # Generate package identifier package
  $package = "${package_name}_url_${architecture}_${compatibility}"

  # Download specific package using extracted URL
  exec { "download_${package}":
    command => "sh -c 'url=\$(grep -F '${package}:' /tmp/arrtifacts_url.txt | tr -d \"\\r\" | cut -d \" \" -f2); curl -o /tmp/${package} \"\$url\"'",
    unless  => "test -f /tmp/${package} && dpkg -I /tmp/${package} >/dev/null 2>&1",
    path    => ['/usr/bin', '/bin', '/sbin', '/usr/sbin'],
    timeout => 600,
  }

  # Install the package using correct provider
  package { "${package_name}":
    ensure   => installed,
    provider => $provider,  # Now using validated provider names
    source   => "/tmp/${package}",
    require  => Exec["download_${package}"],
  }
}
