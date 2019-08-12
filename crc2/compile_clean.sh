#!/bin/bash

if [[ "${CRC2_ROOT}" == "" ]]; then
    echo "CRC2_ROOT not set. Exiting"
    exit -1
fi

rm -rf ${CRC2_ROOT}/bin/*
