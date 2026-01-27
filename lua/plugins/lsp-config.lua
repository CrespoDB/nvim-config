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
					"vtsls",
					"rust_analyzer",
					"clangd",
					"ltex", --  grammar and spell checking
				},
				auto_install = true,
				automatic_enable = {
					exclude = { "eslint" },
				},
			})
		end,
	},
	{
		"mrcjkb/rustaceanvim",
		version = "^5",
		lazy = false,
		ft = { "rust" },
		config = function()
			vim.g.rustaceanvim = {
				server = {
					capabilities = require("cmp_nvim_lsp").default_capabilities(),
					settings = {
						["rust-analyzer"] = {
							cargo = { loadOutDirsFromCheck = true },
							procMacro = { enable = true },
						},
					},
				},
			}
		end,
	},
	{
		"yioneko/nvim-vtsls",
		lazy = false,
		dependencies = { "neovim/nvim-lspconfig" },
		config = function()
			require("lspconfig.configs").vtsls = require("vtsls").lspconfig
		end,
	},
	{
		"neovim/nvim-lspconfig",
		lazy = false,
		config = function()
			local capabilities = require("cmp_nvim_lsp").default_capabilities()

			for _, level in ipairs({ "Error", "Warn", "Info", "Hint" }) do
				local hl = "DiagnosticVirtualText" .. level
				local fg = vim.api.nvim_get_hl(0, { name = "Diagnostic" .. level }).fg
				vim.api.nvim_set_hl(0, hl, { fg = fg, bg = "NONE" })
			end

			vim.diagnostic.config({
				virtual_text = {
					prefix = "●",
					spacing = 4,
				},
				signs = true,
				underline = true,
				update_in_insert = false,
			})

			vim.api.nvim_create_autocmd("LspAttach", {
				callback = function(args)
					local bufnr = args.buf
					local map = function(mode, keys, func, desc)
						vim.keymap.set(mode, keys, func, { buffer = bufnr, noremap = true, silent = true, desc = desc })
					end

					map("n", "K", vim.lsp.buf.hover, "LSP Hover (docs/info)")
					map("n", "<leader>ca", vim.lsp.buf.code_action, "LSP Code Action (fix suggestion)")

					local client = vim.lsp.get_client_by_id(args.data.client_id)
					if client and client.name == "clangd" then
						vim.api.nvim_create_autocmd("BufWritePre", {
							group = vim.api.nvim_create_augroup("ClangFormatOnSave", { clear = true }),
							buffer = bufnr,
							callback = function()
								vim.lsp.buf.format({ timeout_ms = 1000 })
							end,
						})
					end
				end,
			})

			vim.lsp.config("pyright", { capabilities = capabilities })
			vim.lsp.config("vtsls", { capabilities = capabilities })
			vim.lsp.config("gopls", { capabilities = capabilities })
			vim.lsp.config("lua_ls", { capabilities = capabilities })

			vim.lsp.config("clangd", {
				capabilities = capabilities,
				settings = {
					clangd = {
						fallbackFlags = { "-std=c++17" },
					},
				},
			})

			vim.lsp.config("ltex", {
				capabilities = capabilities,
				filetypes = { "markdown", "text" },
				settings = {
					ltex = {
						language = "en-US",
					},
				},
			})

			vim.lsp.enable("pyright")
			vim.lsp.enable("vtsls")
			vim.lsp.enable("gopls")
			vim.lsp.enable("lua_ls")
			vim.lsp.enable("clangd")
			vim.lsp.enable("ltex")
		end,
	},
}
