# Usage of pam user-info module


## Prerequisites

Requires an AAI that can make use of  https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

Select the release repository-archive link to include it in the installation script

## Installation

Example installation on Ubuntu 22.04
```bash
#!/bin/bash

set -e

echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections

echo "Install UserInfo PAM module"
# Add pam headers
sudo apt-get install -q -y libpam-dev libcurl4-openssl-dev
# Download and verify pam_userinfo
cd /opt
sudo wget <repository-archive>
echo "checksum_repository-archive  <repository-archive>" | sudo sha256sum --check
# Extract pam_userinfo to /opt
# Build and install pam_userinfo
sudo tar -xzf <repository-archive>
cd pam_userinfo-<repository-archive>
sudo make
sudo cp pam_userinfo.so /lib/x86_64-linux-gnu/security/.

# Remove the archive
sudo rm /opt/<repository-archive>

echo "Configure UserInfo PAM module"
# Use the module to authenticate xRDP users
sudo sed -i 's/auth       include      password-auth/auth       required     pam_userinfo.so/g' /etc/pam.d/xrdp-sesman
sudo mkdir /etc/pam_userinfo

if [[ -z "${AUD_CLAIM}" ]]; then
    echo "Set the /etc/pam_userinfo/config.json when starting the VM."
else
    # Configure to AAI and set the login audience to match
    # this can be configured also at start up of the VM
    sudo --preserve-env=AUD_CLAIM sh -c 'echo { \"userinfo_endpoint\":\"https://<aai-link>/idp/profile/oidc/userinfo\",\"login_aud\":\"${AUD_CLAIM}\",\"username_matches\":[\"CSCUserName\"]} > /etc/pam_userinfo/config.json'
fi

```