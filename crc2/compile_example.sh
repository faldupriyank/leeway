#!/bin/bash

err_report() {
    echo "Error on line $1"
    rm -rf bin/*
    exit
}

trap 'err_report $LINENO' ERR

if [[ $# -eq 0 ]]; then
    echo "Please provide at least one policy to compile."
    exit
fi

while [[ $# -gt 0 ]]
do
    POLICY=$1
    echo "Compiling for the poliy: ${POLICY}"
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config1 example/${POLICY}.cc lib/config1.a
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config2 example/${POLICY}.cc lib/config2.a
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config3 example/${POLICY}-8MB.cc lib/config3.a
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config4 example/${POLICY}-8MB.cc lib/config4.a
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config5 example/${POLICY}-8MB.cc lib/config5.a
    g++ -Wall --std=c++11 -Iinc -o bin/${POLICY}-config6 example/${POLICY}-8MB.cc lib/config6.a
    shift
done
