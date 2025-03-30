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
				ensure_installed = {
					"lua_ls",
					"gopls",
					"pyright",
					"ts_ls",
					"rust_analyzer",
					"clangd",
					"ltex", --  grammar and spell checking
				},
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

			--
			local on_attach = function(_, bufnr)
				local map = function(mode, keys, func, desc)
					vim.keymap.set(mode, keys, func, { buffer = bufnr, noremap = true, silent = true, desc = desc })
				end

				map("n", "K", vim.lsp.buf.hover, "LSP Hover (docs/info)")
				map("n", "<leader>ca", vim.lsp.buf.code_action, "LSP Code Action (fix suggestion)")
			end

			-- Basic LSP setups
			lspconfig.pyright.setup({ capabilities = capabilities })
			lspconfig.ts_ls.setup({ capabilities = capabilities })
			lspconfig.gopls.setup({ capabilities = capabilities })
			lspconfig.lua_ls.setup({ capabilities = capabilities })

			-- Clangd with autoformat
			lspconfig.clangd.setup({
				capabilities = capabilities,
				on_attach = function(client, bufnr)
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

			--  ltex-ls for Markdown grammar
			lspconfig.ltex.setup({
				capabilities = capabilities,
				on_attach = on_attach,
				filetypes = { "markdown", "text" },
				settings = {
					ltex = {
						language = "en-US",
					},
				},
			})
		end,
	},
}
