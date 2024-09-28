#!/bin/bash
openssl enc -aes256 -pbkdf2 -d -in zeek-test-logs.tar.aes256 -out zeek-test-logs.tar
tar -xvf zeek-test-logs.tar
