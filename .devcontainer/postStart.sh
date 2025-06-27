#!/bin/bash

echo "::step:: Checking for 'devtool' available"
if [ ! -f "./bin/tools/debug/VSOnline.DevTool/DevTool.dll" ]; then
  echo "ERR: DevTool.dll not found."
  exit 1
fi

echo "::step:: Checking for required user secrets"
if [ -z "$DEVELOPER_ALIAS" ]; then
  echo "ERR: The 'DEVELOPER_ALIAS' user secret must be set.  Please consult the README for more information."
  exit 1
fi

echo "::step:: Checking for required repo secrets"
if [ -z "$TUNNEL_KEY" ]; then
  echo "ERR: A required repo secret is missing. Please consult docs/repo-scoped-secrets.md for more information."
  exit 1
fi

CURRENT_TUNNEL_KEY=$(cat /home/codespace/CEDev/appsettings.json | jq -r  .AppSettings.tunnelRelayPrimaryAuthKey)

echo "::step:: Validating ~/CEDev/appsettings.json"
if [ "$CURRENT_TUNNEL_KEY" != "$TUNNEL_KEY" ]; then
  echo "🔀 Updating ~/CEDev/appsettings.json"
  dotnet ./bin/tools/debug/VSOnline.DevTool/DevTool.dll configureSettings --platform Linux --azureRegion WestUs2
else
  echo "🆗 'TUNNEL_KEY' is up to date."
fi
