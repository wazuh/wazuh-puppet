# Class to modify configuration files (YAML or XML)
#
class wazuh::modify_config_file (
  Enum['yaml', 'xml'] $file_type,
  Array[String] $lines, # Now required
  String $config_path = '/path/to/config',
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
          ensure            => present,
          path              => $config_path,
          match             => "^${key}:",
          line              => $value,
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
            "set ${xpath} ${value}",
          ],
        }

        if $force_add_xml {
          augeas { "force_add_xml_${config_path}_${xpath}":
            context => "/files${config_path}",
            changes => [
              "create ${xpath}",
              "set ${xpath} ${value}",
            ],
          }
        }
      } else {
        fail("Invalid XML line format: '${line}'. Expected 'XPath = value'.")
      }
    }
  }
}
