#!/bin/bash

source /etc/lsb-release

echo $DISTRIB_CODENAME
dpkg-query -W
