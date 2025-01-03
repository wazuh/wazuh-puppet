# Class to modify configuration files (YAML or XML)
#
class wazuh::modify_config_file (
  Enum['yaml', 'xml'] $file_type,
  Array[String] $lines,
  String $config_path,
  Boolean $force_add_xml = false
) {
  if $lines.empty {
    fail('No configuration lines provided for processing.')
  }

  if $file_type == 'yaml' {
    # Process configuration lines as YAML (key: value pairs)
    $lines.each |$line| {
      # Validate line format (key: value)
      if $line =~ /^([\w\.\-]+):\s*(.*)$/ {
        $key   = $1
        $value = $line

        file_line { "configure_yaml_${config_path}_${key}":
          ensure             => present,
          path               => $config_path,
          match              => "^${key}:",
          line               => $value,
          append_on_no_match => true,
        }
      } else {
        fail("Invalid YAML line format: '${line}'. Expected 'key: value'.")
      }
    }
  } elsif $file_type == 'xml' {
    # Process configuration lines as XML (XPath = value pairs)
    $lines.each |$line| {
      # Validate XML line format (XPath = value)
      if $line =~ /^(.+?)\s*=\s*(.+)$/ {
        $xpath = $1
        $value = $2

        augeas { "configure_xml_${config_path}_${xpath}":
          context => "/files${config_path}",
          changes => [
            "set ${xpath} ${value}", # Establece el valor en el xpath (crea si no existe)
          ],
          require => Package['augeas-tools'],
        }
        if $force_add_xml {
          augeas { "ensure_xml_${config_path}_${xpath}":
            context => "/files${config_path}",
            changes => [
              "set ${xpath} ${value}",
            ],
            onlyif  => "get ${xpath} != '${value}'", # Solo ejecuta si el valor es diferente o el nodo no existe
            require => Package['augeas-tools'],
            # require => Augeas["configure_xml_${config_path}_${xpath}"], # For order if needed
          }
        }

      } else {
        fail("Invalid XML line format: '${line}'. Expected 'XPath = value'.")
      }
    }

    package { 'augeas-tools':
      ensure => present,
    }
    Class['::augeas_core::params'] -> Package['augeas-tools']
  }
}
