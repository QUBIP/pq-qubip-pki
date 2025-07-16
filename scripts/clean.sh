#!/bin/bash



# Set variables for directory structure
WORKING_DIR=$(pwd)
CA_DIR="certs"

cd $WORKING_DIR
cd ..
rm -rf $CA_DIR crl certs


echo -e "Cleaning everything"
