#!/bin/bash

mkdir -p ~/.nuget/NuGet

tee ~/.nuget/NuGet/NuGet.Config > /dev/null \
<< 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="Cascade" value="https://pkgs.dev.azure.com/devdiv/_packaging/Cascade/nuget/v3/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <Cascade>
      <add key="Username" value="devdiv" />
      <add key="ClearTextPassword" value="%VSS_NUGET_ACCESSTOKEN%" />
    </Cascade>
  </packageSourceCredentials>
</configuration>
EOF