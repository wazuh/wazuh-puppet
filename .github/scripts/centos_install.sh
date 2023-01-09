rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm
ls _ltr /tmp
yes | yum -y install puppet
puppet module install /tmp/wazuh-wazuh-$VERSION.tar.gz
mkdir /etc/puppet/manifests
echo "node "\"$HOSTNAME\"" {" | tee -a /etc/puppet/manifests/wazuh.pp > /dev/null
echo "class {'wazuh::manager'} ->  class {'wazuh::indexer':} -> class {'wazuh::filebeat_oss':} -> class {'wazuh::dashboard':}" | tee -a /etc/puppet/manifests/wazuh.pp > /dev/null
echo "}" | tee -a /etc/puppet/manifests/wazuh.pp > /dev/null
puppet apply /etc/puppet/manifests/wazuh.pp