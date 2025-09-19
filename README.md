# 🧱 Neovim Config Dependencies

## 🗂️ WSL Setup

```bash
wsl --install
```
```bash
sudo apt install ripgrep
```
---

## ⚙️ Neovim (v0.10+ or v0.11+)
This config requires a modern Neovim version.  
Tested with: [https://github.com/CrespoDB/nvim-config](https://github.com/CrespoDB/nvim-config)

Install (AppImage for x86_64):

```bash
curl -LO https://github.com/neovim/neovim/releases/latest/download/nvim-linux-x86_64.appimage
chmod u+x nvim-linux-x86_64.appimage
sudo mv nvim-linux-x86_64.appimage /usr/local/bin/nvim
nvim --version
```

---

## 📥 Install This Config

Clone your config into the correct location:

```bash
rm -rf ~/.config/nvim  # Optional: remove old config
git clone https://github.com/CrespoDB/nvim-config ~/.config/nvim
```

Launch Neovim to let plugins install:

```bash
nvim
```

---

## 🟨 Golang & GolangCI-Lint

```bash
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
```

---

## 🟢 Node.js & Python

```bash
sudo apt update
sudo apt install -y nodejs npm python3 python3-pip unzip curl

# Install language servers globally
sudo npm install -g pyright typescript typescript-language-server
```

---

## 🧹 Fix Permissions (if Mason fails to install)

```bash
sudo chown -R $(whoami):$(whoami) ~/.local/share/nvim
```

---

## 🧽 Clean Up Broken Mason Installs (if needed)

```bash
rm -rf ~/.local/share/nvim/mason/staging/pyright
rm -rf ~/.local/share/nvim/mason/staging/typescript-language-server
rm -rf ~/.local/share/nvim/mason/packages/pyright
rm -rf ~/.local/share/nvim/mason/packages/typescript-language-server
```

---

## 🐍 Pipx (for isolated Python CLI tools)

```bash
sudo apt install -y pipx
pipx ensurepath
pipx --version
```

You may need to restart your shell:

```bash
exec $SHELL
```

---

## 🔧 Install Local Python Scripts (Optional)

```bash
cd ~/.config/nvim/scripts
pipx install .
```

---

## 🦀 Rust & Cargo (for Stylua)

```bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env

# Lua formatter
cargo install stylua
```

---

## 🧼 Clang Format

```bash
sudo apt install -y clang-format
```

---

## 🔁 Restart Shell

```bash
exec $SHELL
```

## 🗂️ Windows Terminal Apperance % Font

![image](https://github.com/user-attachments/assets/6ec02e64-08a0-42ab-a0f6-b060e311cb6e)

Transparency set to 80& Acrylic

## 🗂️ For Markdown

```bash
sudo snap install glow
```

Vault location (can  be changed in obsidian.lua)
```
mkdir -p ~/notes
```

Java needed for speel check LSP (ltex)

```
sudo apt install openjdk-17-jre-headless
```

---

## 🔍 MDR Entity Parser

How to use parsing tool for copied entity data>

1. Copy entity data from Defender/Sentinel alert
2. Paste into Neovim
3. Select the text in visual mode
4. Press `space` + `gm` to format

Converts:
```
Client_IPAddress
80.167.104.143
EmailCount204
```

To:
```
Client IP Address: 80.167.104.143
Email Count: 204
```
## 💰 Auto-Enricher

This will automatically iterate through all elements in the buffer to find interesting indicators (IPs, Hashes, Domains and URLs)

1. Press `space` + `e` to call the enricher, which will display a floating window with details
2. :q to get out of the window

##  Defanger / Refanger

This will use the same iteration as the Auto-Enricher, but will defang the indicators

Write :Defang or :Refang to invoke the tool

