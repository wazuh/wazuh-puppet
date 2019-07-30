#!/bin/bash

rm -rf .kitchen/logs/*
rm -rf .kitchen/def*
rm -rf ./manifests/se*
kitchen destroy all
docker rm -f $(docker ps -aq)
kitchen create
ubuntu_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  ubuntu | grep manager`)"
centos_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  centos | grep manager`)"
cp ./manifests/site.pp.template ./manifests/site.pp
sed -i 's/ubuntu_manager_ip/'${ubuntu_manager_ip}'/g' ./manifests/site.pp
sed -i 's/centos_manager_ip/'${centos_manager_ip}'/g' ./manifests/site.pp
kitchen converge
kitchen verify
