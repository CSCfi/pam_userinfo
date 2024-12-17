#!/bin/sh
if [ ! -d "/home/${PAM_USER}" ]; then
  adduser --disabled-password --gecos "" ${PAM_USER}
  usermod -a -G users ${PAM_USER}
fi