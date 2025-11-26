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
		"neovim/nvim-lspconfig",
		lazy = false,
		config = function()
			local capabilities = require("cmp_nvim_lsp").default_capabilities()

			local on_attach = function(_, bufnr)
				local map = function(mode, keys, func, desc)
					vim.keymap.set(mode, keys, func, { buffer = bufnr, noremap = true, silent = true, desc = desc })
				end

				map("n", "K", vim.lsp.buf.hover, "LSP Hover (docs/info)")
				map("n", "<leader>ca", vim.lsp.buf.code_action, "LSP Code Action (fix suggestion)")
			end

			-- Configure LSP servers using new vim.lsp.config API
			vim.lsp.config.pyright = {
				capabilities = capabilities,
			}

			vim.lsp.config.ts_ls = {
				capabilities = capabilities,
			}

			vim.lsp.config.gopls = {
				capabilities = capabilities,
			}

			vim.lsp.config.lua_ls = {
				capabilities = capabilities,
			}

			-- Clangd with autoformat
			vim.lsp.config.clangd = {
				capabilities = capabilities,
				on_attach = function(client, bufnr)
					vim.api.nvim_create_autocmd("BufWritePre", {
						group = vim.api.nvim_create_augroup("ClangFormatOnSave", { clear = true }),
						buffer = bufnr,
						callback = function()
							vim.lsp.buf.format({ timeout_ms = 1000 })
						end,
					})
				end,
				settings = {
					clangd = {
						fallbackFlags = { "-std=c++17" },
					},
				},
			}

			-- ltex-ls for Markdown grammar
			vim.lsp.config.ltex = {
				capabilities = capabilities,
				on_attach = on_attach,
				filetypes = { "markdown", "text" },
				settings = {
					ltex = {
						language = "en-US",
					},
				},
			}

			-- Auto-start LSP servers for appropriate filetypes
			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "python" },
				callback = function()
					vim.lsp.start(vim.lsp.config.pyright)
				end,
			})

			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "typescript", "javascript", "typescriptreact", "javascriptreact" },
				callback = function()
					vim.lsp.start(vim.lsp.config.ts_ls)
				end,
			})

			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "go" },
				callback = function()
					vim.lsp.start(vim.lsp.config.gopls)
				end,
			})

			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "lua" },
				callback = function()
					vim.lsp.start(vim.lsp.config.lua_ls)
				end,
			})

			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "c", "cpp" },
				callback = function()
					vim.lsp.start(vim.lsp.config.clangd)
				end,
			})

			vim.api.nvim_create_autocmd("FileType", {
				pattern = { "markdown", "text" },
				callback = function()
					vim.lsp.start(vim.lsp.config.ltex)
				end,
			})
		end,
	},
}
