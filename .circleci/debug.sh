#!/usr/bin/env bash

if [ -z "${GPG_KEY_BASE64}" ];
then
  echo "not GPG_KEY_BASE64";
else
  echo "yupp GPG_KEY_BASE64";
fi

if [ -z "${GPG_KEY_NAME}" ];
then
  echo "not GPG_KEY_NAME";
else
  echo "yupp GPG_KEY_NAME";
fi

if [ -z "${GPG_PASSPHRASE}" ];
then
  echo "not GPG_PASSPHRASE";
else
  echo "yupp GPG_PASSPHRASE";
fi

gpg --version