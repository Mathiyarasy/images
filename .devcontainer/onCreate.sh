#!/bin/bash

set -e # If any command below fails, exit the script with an error and fail the prebuild.
df -h
exit 0
# The root folder path of the repo in a Codespace
ROOT_FOLDER="/workspaces/codespaces-service"

RED='\033[0;91m'
REDBOLD='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
YELLOWBOLD='\033[1;93m'
BOLD='\033[1m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
function print_status() {
  echo -e "${YELLOWBOLD}[+] $1${NC}"
}
function print_error() {
  echo -e "${REDBOLD}[-] $1${NC}"
}

print_status "Starting 'onCreate.sh' to prebuild the 'github/codespaces-service' environment..."

# Required Repo-Scoped Secrets
# See: docs/repo-scoped-secrets.md
if [ -z "$TUNNEL_KEY" ] || [ -z "$APP_SECRET" ]; then
  print_error "A required Repo secret is missing. Please consult docs/repo-scoped-secrets.md for more information."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

git fetch --unshallow || : # REMOVE if no longer seeing 'Nerdbank.GitVersioning.GitException'

print_status "Installing apt dependencies"
sudo apt update -yq
sudo apt install -yq \
    cifs-utils \
    tmux \
    xvfb \
    lcov \
    make \
    lvm2

mkdir -p ~/CEDev

if [ ! -f global.json ]; then
  print_error "Expects a file 'global.json' setting the global dotnet version."
  exit 1
fi

pushd /tmp
  wget https://dot.net/v1/dotnet-install.sh
  chmod +x ./dotnet-install.sh

  print_status "Installing dotnet 8.0.3xx latest"
  ./dotnet-install.sh --channel 8.0.3xx --install-dir /home/codespace/.dotnet

  rm dotnet-install.sh
popd
sudo apt install -yq powershell
print_status "Installing tools"
./tools/Powershell/install-cosmos-db.ps1
./tools/bash/setup-seq.sh
./tools/bash/setup-azurite.sh

GLOBAL_BASH_CONFIG="/etc/bash.bashrc"
GLOBAL_ZSH_CONFIG="/etc/zsh/zshrc"

# Git Defaults
git config pull.rebase false
git config core.autocrlf false

CXC_ALIASES="

if [ -f ~/.cs-environment ]; then
    source ~/.cs-environment
fi

function codespaces-info() {
  $ROOT_FOLDER/tools/Powershell/codespaces-info.ps1 $@
}

alias ports='lsof -n -i -P | grep TCP'
alias devtool=\"dotnet $ROOT_FOLDER/bin/tools/debug/VSOnline.DevTool/DevTool.dll\"
alias vsoutil=\"dotnet $ROOT_FOLDER/bin/service/debug/VsoUtil/VsoUtil.dll\"

alias watch-devstamp=\"$ROOT_FOLDER/tools/bash/watch-devstamp.sh\"
alias save-dashboards=\"mkdir -p $ROOT_FOLDER/tools/seq/template && seqcli template export -o $ROOT_FOLDER/tools/seq/template\"

# vmagent-local quick alias
# - lcomp => shell into local-compute container
# - lcode => shell into codespace container inside the local-compute container
# - lstandalone => shell into local-standalone container
# - vmloc => change directory to vmagent-local
alias lcomp=\"docker exec -it local-compute /bin/bash\"
alias lcode=\"docker exec -it local-compute sh -c 'docker exec -it \\\"\\\$(docker ps -q -a --filter label=Type=codespaces)\\\" /bin/bash'\"
alias lstandalone=\"docker exec -it local-standalone /bin/bash\"
alias vmloc=\"pushd $ROOT_FOLDER/src/agent/vmagent-local/\"

export PATH=\$PATH:$ROOT_FOLDER/.codespaces:$ROOT_FOLDER/tools/bash:$ROOT_FOLDER/tools/Powershell:/home/codespace/.dotnet/tools

# Setting BASH_ENV ensures that any non-interactive terminals which get spawned from an interactive terminal will still use the auth helper
# For example, this is the case in 'dotnet build' where the top level shell is interactive, but sub-shells are non-interactive.
export BASH_ENV=$HOME/.ado-auth-helper.sh
. \$BASH_ENV
"

print_status "Append aliases to bashrc and zshrc..."
echo "${CXC_ALIASES}" | sudo tee -a "${GLOBAL_BASH_CONFIG}" > /dev/null
echo "${CXC_ALIASES}" | sudo tee -a "${GLOBAL_ZSH_CONFIG}" > /dev/null

print_status " Installing Azure AzCopy"
pushd /tmp
    wget https://aka.ms/downloadazcopy-v10-linux
    tar xvf downloadazcopy-v10-linux
    sudo cp ./azcopy_linux_amd64_*/azcopy /usr/local/bin
    sudo chmod +x /usr/local/bin/azcopy
popd

ACTION_NAME="$(cat /workspaces/.codespaces/shared/environment-variables.json | jq -r '.ACTION_NAME')"
echo "The current build has an action name of: $ACTION_NAME"

print_status "Setting up npmrc credentials"
.devcontainer/setup-npmrc.sh

print_status "Setting up nuget credentials"
.devcontainer/setup-nuget.sh

# ONLY run this step during prebuild template creation.
if [ ! -z "$ACTION_NAME" ] && [ "$ACTION_NAME" == "createPrebuildTemplate" ]; then
  print_status "Starting login to Azure with ODIC"
  AZURE_CLIENT_ID="1771cf65-4b36-4436-bd05-cd9819ab5023"
  AZURE_TENANT_ID="72f988bf-86f1-41af-91ab-2d7cd011db47"
  AZURE_SUBSCRIPTION_ID="c2ed6b9a-429d-467d-9949-da0202b12ac8"

  response=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange")
  federatedToken=$(echo $response | jq -r '.value')

  az login --service-principal -u $AZURE_CLIENT_ID --tenant $AZURE_TENANT_ID --federated-token "$federatedToken"
  az account set --subscription $AZURE_SUBSCRIPTION_ID

  print_status "Azure login with ODIC succeeded"

  # DO NOT RENAME these variables, ghcr.io/microsoft/codespace-features/artifacts-helper requires them for authentication
  export ARTIFACTS_ACCESSTOKEN=$(az account get-access-token --tenant $AZURE_TENANT_ID --query accessToken -o tsv)
  export VSS_NUGET_ACCESSTOKEN=$ARTIFACTS_ACCESSTOKEN

fi

print_status "Setting up git hooks"
git config --local core.hooksPath .githooks/

# ONLY run this step during prebuild template creation.
if [ ! -z "$ACTION_NAME" ] && [ "$ACTION_NAME" == "createPrebuildTemplate" ]; then
  print_status "setting up rust.."
  .devcontainer/setup-rust.sh

  print_status "Build service and agent"
  .pipelines/build-service-and-agent.sh --build-config=debug --skip-tests

  print_status "Build tools"
  dotnet build tools/DevTool
  dotnet build src/service/Utility/VsoUtil
  tools/bash/setup-reverse-shell-vm.sh

  print_status "Build CxC extension"
  npm install -g vsce typescript
  pushd $ROOT_FOLDER/tools/extension/cxc
      npm install
      echo y | vsce package -o cxc.vsix
  popd
fi

export PS_PROFILE=~/.config/powershell/Microsoft.PowerShell_profile.ps1
mkdir -p "$(dirname "$PS_PROFILE")" && touch "$PS_PROFILE"
echo "
using module $ROOT_FOLDER/tools/Powershell/codespaces-db
" >> $PS_PROFILE

# Cache the images needed for vmagent-local and the VMAgent local component tests
# ONLY run this step during prebuild template creation.
# NOTE: This check is an exception to the behavior we preach to our users ;)
if [ ! -z "$ACTION_NAME" ] && [ "$ACTION_NAME" == "createPrebuildTemplate" ]; then
  print_status "Caching vmagent-local images"
  pushd $ROOT_FOLDER/src/agent/vmagent-local
    PREBUILD=true bash ./setup.sh codespace-prebuild
    EXITCODE=$?
    print_status "Prebuilding vmagent-local exited with code: $EXITCODE"
    if [ $EXITCODE -ne 0 ]; then
      print_error "Prebuilding artifacts for vmagent-local failed."
      exit $EXITCODE
    fi
  popd
else
  print_status "Skipping auto-caching of 'vmagent-local' images. ACTION_NAME must be \"createPrebuildTemplate\" to cache."
fi

print_status "Installing dev tunnels"
curl -sL https://aka.ms/DevTunnelCliInstall | bash

print_status "Setting up $YELLOW'storage-driver-rs'$NC project"

make -C $ROOT_FOLDER/src/agent/PrebuildArtifacts/storage-driver-rs setup

echo; print_status "Configuration Complete!"
