return {
	"nvimtools/none-ls.nvim", -- Ensure this points to the correct null-ls repository
	config = function()
		local null_ls = require("null-ls")

		null_ls.setup({
			sources = {
				-- Formatting sources
				null_ls.builtins.formatting.stylua,
				null_ls.builtins.formatting.gofmt,
				-- Diagnostics source
				null_ls.builtins.diagnostics.golangci_lint.with({
					extra_args = { "--fast" },
				}),
			},
		})

		-- Auto-format on save
		vim.api.nvim_create_autocmd("BufWritePre", {
			pattern = { "*.go", "*.lua" },
			callback = function()
				vim.lsp.buf.format()
			end,
		})
		vim.keymap.set("n", "<leader>gf", vim.lsp.buf.format, {})
	end,
}
