#!/bin/bash

rm -rf .kitchen/logs/* # removing old logs
rm -rf .kitchen/def* # removing old .yml files associated for old kitchen instances
rm -rf ./manifests/se* # removing all temporal manifests files.

kitchen destroy all # destroying all existing kitchen instances
docker rm -f $(docker ps -aq) # removing all existing containers.

kitchen create # creating new kitchen instances

# getting Wazuh managers IPs.
ubuntu_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  ubuntu | grep manager`)"
centos_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  centos | grep manager`)"

# getting a backup of ./manifests/site.pp.template
cp ./manifests/site.pp.template ./manifests/site.pp

# Assigning Wazuh managers IPs to the corresponding agents.
sed -i 's/ubuntu_manager_ip/'${ubuntu_manager_ip}'/g' ./manifests/site.pp
sed -i 's/centos_manager_ip/'${centos_manager_ip}'/g' ./manifests/site.pp

# Installing the configured wazuh manifests.
kitchen converge

# Testing
kitchen verify
