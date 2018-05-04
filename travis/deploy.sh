#!/bin/bash -e
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
  openssl aes-256-cbc -K $encrypted_5569a6fe8f7a_key -iv $encrypted_5569a6fe8f7a_iv \
  -in travis/codesigning.asc.enc -out travis/codesigning.asc -d
    gpg --fast-import travis/codesigning.asc
    mvn --settings travis/settings.xml deploy -Prelease -DskipTests=true
fi
