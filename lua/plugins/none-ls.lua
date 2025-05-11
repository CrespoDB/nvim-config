return {
	"nvimtools/none-ls.nvim",
	config = function()
		local null_ls = require("null-ls")
		null_ls.setup({
			sources = {
				null_ls.builtins.formatting.stylua,
				null_ls.builtins.formatting.gofmt,
				null_ls.builtins.diagnostics.golangci_lint.with({
					extra_args = { "--fast" },
				}),
				null_ls.builtins.formatting.clang_format.with({
					extra_args = { "--style=llvm" },
				}),
			},
		})

		-- Auto-format on save
		vim.api.nvim_create_autocmd("BufWritePre", {
			pattern = { "*.go", "*.lua", "*.c", "*.cpp" },
			callback = function()
				vim.lsp.buf.format()
			end,
		})
		vim.keymap.set("n", "<leader>gf", vim.lsp.buf.format, {})
	end,
}
