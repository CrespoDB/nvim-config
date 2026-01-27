# Neovim Config Dependencies

## WSL Setup

wsl --install

sudo apt install ripgrep

## Neovim (v0.10+ or v0.11+)
This config requires a modern Neovim version.  
Tested with: https://github.com/CrespoDB/nvim-config

Install (AppImage for x86_64):

curl -LO https://github.com/neovim/neovim/releases/latest/download/nvim-linux-x86_64.appimage
chmod u+x nvim-linux-x86_64.appimage
sudo mv nvim-linux-x86_64.appimage /usr/local/bin/nvim
nvim --version

## Install This Config

Clone your config into the correct location:

rm -rf ~/.config/nvim  # Optional: remove old config
git clone https://github.com/CrespoDB/nvim-config ~/.config/nvim

Launch Neovim to let plugins install:

nvim

## Golang & GolangCI-Lint

# Install Go
curl -LO https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b ~/.local/bin v1.55.2
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

## Node.js & Python

sudo apt update
sudo apt install -y nodejs npm python3 python3-pip unzip curl

# Install language servers globally
sudo npm install -g pyright typescript typescript-language-server

## Fix Permissions (if Mason fails to install)

sudo chown -R $(whoami):$(whoami) ~/.local/share/nvim

## Clean Up Broken Mason Installs (if needed)

rm -rf ~/.local/share/nvim/mason/staging/pyright
rm -rf ~/.local/share/nvim/mason/staging/typescript-language-server
rm -rf ~/.local/share/nvim/mason/packages/pyright
rm -rf ~/.local/share/nvim/mason/packages/typescript-language-server

Install VTLS via Mason (If not already installed via LSP config)
Install eslint_d linter via Mason
Install Prettierd Formatter via Mason

## Pipx (for isolated Python CLI tools)

sudo apt install -y pipx
pipx ensurepath
pipx --version

You may need to restart your shell:

exec $SHELL

## Install Local Python Scripts (Optional)

cd ~/.config/nvim/scripts
pipx install .

## Rust & Cargo (for Stylua)

curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env

# Lua formatter
cargo install stylua

## Clang Format

sudo apt install -y clang-format

## Restart Shell

exec $SHELL

## Windows Terminal Appearance & Font

{
    "$help": "https://aka.ms/terminal-documentation",
    "$schema": "https://aka.ms/terminal-profiles-schema",
    "actions": 
    [
        {
            "command": 
            {
                "action": "copy",
                "singleLine": false
            },
            "id": "User.copy.644BA8F2"
        },
        {
            "command": "paste",
            "id": "User.paste"
        },
        {
            "command": "find",
            "id": "User.find"
        },
        {
            "command": 
            {
                "action": "splitPane",
                "split": "auto",
                "splitMode": "duplicate"
            },
            "id": "User.splitPane.A6751878"
        }
    ],
    "copyFormatting": "none",
    "copyOnSelect": false,
    "defaultProfile": "{46ca431a-3a87-5fb3-83cd-11ececc031d2}",
    "keybindings": 
    [
        {
            "id": "User.copy.644BA8F2",
            "keys": "ctrl+c"
        },
        {
            "id": "User.paste",
            "keys": "ctrl+v"
        },
        {
            "id": "User.find",
            "keys": "ctrl+shift+f"
        },
        {
            "id": "User.splitPane.A6751878",
            "keys": "alt+shift+d"
        }
    ],
    "newTabMenu": 
    [
        {
            "type": "remainingProfiles"
        }
    ],
    "profiles": 
    {
        "defaults": 
        {
            "adjustIndistinguishableColors": "always",
            "colorScheme": "DayFox",
            "cursorShape": "filledBox",
            "experimental.retroTerminalEffect": false,
            "font": 
            {
                "cellHeight": "1.1",
                "face": "CaskaydiaCove Nerd Font",
                "size": 12,
                "weight": "semi-bold"
            },
            "intenseTextStyle": "all",
            "opacity": 100
        },
        "list": 
        [
            {
                "guid": "{574e775e-4f2a-5b96-ac1e-a2962a402336}",
                "hidden": false,
                "name": "PowerShell",
                "source": "Windows.Terminal.PowershellCore"
            },
            {
                "adjustIndistinguishableColors": "always",
                "experimental.retroTerminalEffect": false,
                "guid": "{46ca431a-3a87-5fb3-83cd-11ececc031d2}",
                "hidden": false,
                "name": "kali-linux",
                "source": "Windows.Terminal.Wsl",
            },
            {
                "commandline": "%SystemRoot%\\System32\\cmd.exe",
                "guid": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
                "hidden": false,
                "name": "Command Prompt"
            },
            {
                "colorScheme": "One Half Light Npa",
                "font": 
                {
                    "face": "CaskaydiaCove Nerd Font",
                    "size": 12,
                    "weight": "medium"
                },
                "guid": "{51855cb2-8cce-5362-8f54-464b92b32386}",
                "hidden": false,
                "name": "Ubuntu",
                "source": "CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc"
            },
            {
                "guid": "{2c4de342-38b7-51cf-b940-2309a097f518}",
                "hidden": true,
                "name": "Ubuntu",
                "source": "Windows.Terminal.Wsl"
            },
            {
                "commandline": "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "guid": "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}",
                "hidden": false,
                "name": "Windows PowerShell"
            },
            {
                "guid": "{e9d77d9e-37cc-59f3-8599-b45f90da72a4}",
                "hidden": false,
                "name": "Developer Command Prompt for VS 2019",
                "source": "Windows.Terminal.VisualStudio"
            },
            {
                "guid": "{bfa3e35a-fcdf-5ad5-b3f2-605b9f6e967c}",
                "hidden": false,
                "name": "Developer PowerShell for VS 2019",
                "source": "Windows.Terminal.VisualStudio"
            },
            {
                "guid": "{2ece5bfe-50ed-5f3a-ab87-5cd4baafed2b}",
                "hidden": false,
                "name": "Git Bash",
                "source": "Git"
            },
            {
                "guid": "{b453ae62-4e3d-5e58-b989-0a998ec441b8}",
                "hidden": false,
                "name": "Azure Cloud Shell",
                "source": "Windows.Terminal.Azure"
            }
        ]
    },
    "schemes": 
    [
        {
            "background": "#1B1E2E",
            "black": "#0C0C0C",
            "blue": "#0037DA",
            "brightBlack": "#767676",
            "brightBlue": "#3B78FF",
            "brightCyan": "#61D6D6",
            "brightGreen": "#16C60C",
            "brightPurple": "#B4009E",
            "brightRed": "#E74856",
            "brightWhite": "#F2F2F2",
            "brightYellow": "#F9A732",
            "cursorColor": "#FFFFFF",
            "cyan": "#3A96DD",
            "foreground": "#FFFFFF",
            "green": "#13A10E",
            "name": "Campbell (modified)",
            "purple": "#881798",
            "red": "#C50F1F",
            "selectionBackground": "#FFFFFF",
            "white": "#CCCCCC",
            "yellow": "#C16717"
        },
        {
            "background": "#080808",
            "black": "#000000",
            "blue": "#2472C8",
            "brightBlack": "#666666",
            "brightBlue": "#3B8EEA",
            "brightCyan": "#29B8DB",
            "brightGreen": "#23D18B",
            "brightPurple": "#D670D6",
            "brightRed": "#F14C4C",
            "brightWhite": "#E5E5E5",
            "brightYellow": "#F5BA0A",
            "cursorColor": "#808080",
            "cyan": "#11A8CD",
            "foreground": "#CCCCCC",
            "green": "#0DBC79",
            "name": "Dark+ Npa",
            "purple": "#BC3FBC",
            "red": "#CD3131",
            "selectionBackground": "#FFFFFF",
            "white": "#E5E5E5",
            "yellow": "#F5BA0A"
        },
        {
            "background": "#F6F2EE",
            "black": "#352C24",
            "blue": "#2948AB",
            "brightBlack": "#534C45",
            "brightBlue": "#506EC9",
            "brightCyan": "#488D93",
            "brightGreen": "#577F63",
            "brightPurple": "#8452D5",
            "brightRed": "#B3434E",
            "brightWhite": "#F4ECE6",
            "brightYellow": "#B86E28",
            "cursorColor": "#3D2B5A",
            "cyan": "#287980",
            "foreground": "#3D2B5A",
            "green": "#396847",
            "name": "DayFox",
            "purple": "#6E33CE",
            "red": "#A5222F",
            "selectionBackground": "#E7D2BE",
            "white": "#F2E9E1",
            "yellow": "#AC5402"
        },
        {
            "background": "#FAFAFA",
            "black": "#383A42",
            "blue": "#0184BC",
            "brightBlack": "#4F525D",
            "brightBlue": "#61AFEF",
            "brightCyan": "#56B5C1",
            "brightGreen": "#98C379",
            "brightPurple": "#C577DD",
            "brightRed": "#DF6C75",
            "brightWhite": "#A8A8A8",
            "brightYellow": "#E0AA09",
            "cursorColor": "#4F525D",
            "cyan": "#0997B3",
            "foreground": "#383A42",
            "green": "#50A14F",
            "name": "One Half Light Npa",
            "purple": "#A626A4",
            "red": "#E45649",
            "selectionBackground": "#383A42",
            "white": "#575757",
            "yellow": "#E0AA09"
        },
        {
            "background": "#000000",
            "black": "#000000",
            "blue": "#000080",
            "brightBlack": "#808080",
            "brightBlue": "#0000FF",
            "brightCyan": "#00FFFF",
            "brightGreen": "#00FF00",
            "brightPurple": "#FF00FF",
            "brightRed": "#FF0000",
            "brightWhite": "#FFFFFF",
            "brightYellow": "#FF9908",
            "cursorColor": "#FFFFFF",
            "cyan": "#008080",
            "foreground": "#C0C0C0",
            "green": "#008000",
            "name": "Vintage (Copy)",
            "purple": "#800080",
            "red": "#800000",
            "selectionBackground": "#FFFFFF",
            "white": "#C0C0C0",
            "yellow": "#BD7A07"
        }
    ],
    "theme": "legacyLight",
    "themes": [],
    "useAcrylicInTabRow": true
}

Font: JetBrainsMono Nerd Font

## For Markdown

sudo snap install glow

Vault location (can be changed in obsidian.lua)

mkdir -p ~/notes

Java needed for spell check LSP (ltex)

sudo apt install openjdk-17-jre-headless

## MDR Entity Parser

How to use parsing tool for copied entity data:

1. Copy entity data from Defender/Sentinel alert
2. Paste into Neovim
3. Select the text in visual mode
4. Press space + gm to format

Converts:
Client_IPAddress
80.167.104.143
EmailCount204

To:
Client IP Address: 80.167.104.143
Email Count: 204

## Auto-Enricher

This will automatically iterate through all elements in the buffer to find interesting indicators (IPs, Hashes, Domains and URLs)

1. Press space + e to call the enricher, which will display a floating window with details
2. :q to get out of the window

## Defanger / Refanger

This will use the same iteration as the Auto-Enricher, but will defang the indicators

Write :Defang or :Refang to invoke the tool
