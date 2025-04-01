local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not vim.loop.fs_stat(lazypath) then
  vim.fn.system({
    "git",
    "clone",
    "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable", -- latest stable release
    lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)
vim.opt.relativenumber = true

require("vim-options")
require("lazy").setup("plugins")
require("autocmds.defang")
require("cmds.ticket").setup()

vim.schedule(function()
  if vim.lsp.get_clients == nil then
    print("⚠️  vim.lsp.get_clients is nil. Restoring...")
    vim.lsp.get_clients = vim.lsp.get_active_clients
  end
end)
