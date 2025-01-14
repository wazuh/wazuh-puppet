# Class to modify configuration files (YAML or XML)
#
# @param file_path The path to the configuration file to be modified
# @param key_value_pairs An array of key-value pairs to be updated in the configuration file
class wazuh::modify_config_file (
  String $file_path,
  Array $key_value_pairs,
) {

  # Asegura que el archivo exista con contenido inicial si no existe
  file { $file_path:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => "# Initial content\n",
  }

  # Leer contenido actual del archivo
  $current_content = file($file_path)

  # Genera contenido actualizado basado en las claves y valores
  $new_content = inline_template(@(END))
<% |
  String current_content,
  Array key_value_pairs
| -%>
<%- # Divide el contenido actual en líneas -%>
<%- lines = current_content.split("\n") -%>
<%- # Convierte pares clave-valor en un hash -%>
<%- pairs = key_value_pairs.map { |pair| pair.split(":", 2) } -%>
<%- hash = pairs.reduce({}) { |acc, item| acc.merge({ item[0].strip => item[1].strip }) } -%>
<%- # Modifica líneas existentes o agrega nuevas líneas -%>
<%- result = lines.map { |line|
  key = line.split(":")[0].strip
  if hash.key?(key)
    "#{key}: #{hash.delete(key)}"
  else
    line
  end
} + hash.map { |key, value| "#{key}: #{value}" } -%>
<%= result.join("\n") %>
END
  )

  # Aplica el contenido actualizado al archivo
  file { $file_path:
    ensure  => file,
    content => $new_content,
  }
}
