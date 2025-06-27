#!/bin/bash

tee ~/.npmrc > /dev/null \
<< 'EOF'
; begin auth token
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/registry/:username=oauth
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/registry/:_authToken=${ARTIFACTS_ACCESSTOKEN}
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/registry/:email=npm requires email to be set but doesn't use the value
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/:username=oauth
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/:_authToken=${ARTIFACTS_ACCESSTOKEN}
//devdiv.pkgs.visualstudio.com/_packaging/Cascade/npm/:email=npm requires email to be set but doesn't use the value
; end auth token
EOF
