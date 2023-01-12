rpm -Uvh https://yum.puppetlabs.com/puppet5/puppet5-release-el-7.noarch.rpm
ls -ltr /tmp
yes | yum -y install puppet
ln -s /opt/puppetlabs/bin/puppet /bin
puppet module install /tmp/wazuh-wazuh-$VERSION.tar.gz
mkdir /etc/puppet/manifests
/etc/puppetlabs/code/environments/production/manifests/
echo "node "\"$HOSTNAME\"" {" | tee -a /etc/puppet/manifests/wazuh.pp > /dev/null
echo "node "\"$HOSTNAME\"" {" | tee -a /etc/puppetlabs/code/environments/production/manifests/wazuh.pp > /dev/null
echo "  class {'wazuh::manager':} ->  class {'wazuh::indexer':} -> class {'wazuh::filebeat_oss':} -> class {'wazuh::dashboard':}" | tee -a /etc/puppetlabs/code/environments/production/manifests/wazuh.pp > /dev/null
echo "}" | tee -a /etc/puppetlabs/code/environments/production/manifests/wazuh.pp > /dev/null
cat /etc/puppet/manifests/wazuh.pp
puppet apply /etc/puppetlabs/code/environments/production/manifests/wazuh.pp
ls -ltr /var/ossec