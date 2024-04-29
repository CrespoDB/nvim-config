return {
	{
		"williamboman/mason.nvim",
		lazy = false,
		config = function()
			require("mason").setup()
		end,
	},
	{
		"williamboman/mason-lspconfig.nvim",
		lazy = false,
		config = function()
			require("mason-lspconfig").setup({
				ensure_installed = { "lua_ls", "gopls", "pyright", "tsserver", "rust_analyzer", "clangd" }, -- added clangd
				auto_install = true,
			})
		end,
	},
	{
		"simrat39/rust-tools.nvim",
		config = function()
			require("rust-tools").setup({
				server = {
					on_attach = function(_, bufnr)
						require("rust-tools").mappings(bufnr)
					end,
					capabilities = require("cmp_nvim_lsp").default_capabilities(),
					settings = {
						["rust-analyzer"] = {
							cargo = { loadOutDirsFromCheck = true },
							procMacro = { enable = true },
						},
					},
				},
			})
		end,
	},
	{
		"neovim/nvim-lspconfig",
		lazy = false,
		config = function()
			local capabilities = require("cmp_nvim_lsp").default_capabilities()
			local lspconfig = require("lspconfig")
			-- Basic setups for other languages
			lspconfig.pyright.setup({ capabilities = capabilities })
			lspconfig.tsserver.setup({ capabilities = capabilities })
			lspconfig.gopls.setup({ capabilities = capabilities })
			lspconfig.lua_ls.setup({ capabilities = capabilities })
			-- Enhanced clangd setup with formatting
			lspconfig.clangd.setup({
				capabilities = capabilities,
				on_attach = function(client, bufnr)
					-- Enable automatic formatting on buffer save
					vim.api.nvim_create_autocmd("BufWritePre", {
						group = vim.api.nvim_create_augroup("ClangFormatOnSave", { clear = true }),
						buffer = bufnr,
						callback = function()
							vim.lsp.buf.formatting_sync(nil, 1000)
						end,
					})
				end,
				settings = {
					clangd = {
						fallbackFlags = { "-std=c++17" },
					},
				},
			})
		end,
	},
}
