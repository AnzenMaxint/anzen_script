#!/usr/bin/env bash

set -euxo pipefail

source /etc/os-release
[[ -n ${UBUNTU_CODENAME:-} ]] || {
  echo "Unable to determine Ubuntu version" >&2
  exit 1
}

case ${UBUNTU_CODENAME} in 
  jammy|focal|bionic)
    UBUNTU_LTS=${UBUNTU_CODENAME}
    ;;
  lunar|kinetic|mantic)
    UBUNTU_LTS=jammy
    ;;
  impish|hirsute|groovy)
    UBUNTU_LTS=focal
    ;;
  eoan|disco|cosmic)
    UBUNTU_LTS=bionic
    ;;
  *)
    echo "WARN: Ubuntu version: ${UBUNTU_CODENAME} not recognized, assuming latest" >&2
    UBUNTU_LTS=jammy
    ;;
esac

curl -sSLf https://get.openanzen.io/tun/package-repos.gpg \
  | sudo gpg --dearmor --output /usr/share/keyrings/openanzen.gpg

sudo chmod +r /usr/share/keyrings/openanzen.gpg

echo "deb [signed-by=/usr/share/keyrings/openanzen.gpg] https://packages.openanzen.org/anzenpax-openanzen-deb-stable ${UBUNTU_LTS} main" \
  | sudo tee /etc/apt/sources.list.d/openanzen.list >/dev/null

sudo apt-get update
sudo apt-get install --yes anzen-edge-tunnel
