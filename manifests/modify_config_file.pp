# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {

  # Asegura que el archivo existe antes de modificarlo
  file { $file_path:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => "# Initial content\n", # Contenido inicial si no existe
  }

  # Genera contenido actualizado basado en las claves y valores
  $new_content = inline_template(@(END))
<% |
  String $current_content,
  Array $key_value_pairs
| -%>
<%- # Divide el contenido actual en líneas -%>
<%- $lines = $current_content.split("\n") -%>
<%- # Convierte pares clave-valor en un hash -%>
<%- $pairs = $key_value_pairs.map |$pair| { split($pair, ':', 2) } -%>
<%- $hash = $pairs.reduce({}) |$acc, $item| { $acc + { $item[0] => $item[1] } } -%>
<%- # Modifica líneas existentes o agrega nuevas líneas -%>
<%- $result = $lines.map |$line| {
  if $hash.has_key($line.split(':')[0]) {
    $line.split(':')[0] + ": " + $hash.delete($line.split(':')[0])
  } else {
    $line
  }
} + $hash.map |$key, $value| { $key + ": " + $value } -%>
<%= $result.join("\n") -%>
END
    $current_content => file($file_path),
    $key_value_pairs => $key_value_pairs,
  )

  # Aplica el contenido modificado al archivo
  file { $file_path:
    ensure  => file,
    content => $new_content,
  }
}
