#!/bin/bash -e
if [ "$TRAVIS_BRANCH" = 'master' ] && [ "$TRAVIS_PULL_REQUEST" == 'false' ]; then
  openssl aes-256-cbc -K $encrypted_91adec119052_key -iv $encrypted_91adec119052_iv \
  -in travis/codesigning.asc.enc -out travis/codesigning.asc -d
    gpg --fast-import travis/codesigning.asc
    mvn --settings travis/settings.xml deploy -Prelease,deploy-to-sonatype -DskipTests=true
fi
