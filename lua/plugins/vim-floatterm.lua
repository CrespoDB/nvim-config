return {
	"voldikss/vim-floaterm",
	config = function()
		-- Adjusts the size and appearance of the floaterm
		vim.g.floaterm_width = 0.7
		vim.g.floaterm_height = 0.7
		vim.g.floaterm_wintype = "float"
		vim.g.floaterm_position = "center"

		-- Key mappings for vim-floaterm
		vim.api.nvim_set_keymap("n", "<leader>ft", ":FloatermToggle<CR>", { noremap = true, silent = true })
		vim.api.nvim_set_keymap("t", "<leader>ft", "<C-\\><C-n>:FloatermToggle<CR>", { noremap = true, silent = true })
		vim.api.nvim_set_keymap("n", "<leader>fn", ":FloatermNew<CR>", { noremap = true, silent = true })

		vim.cmd([[
        hi Floaterm guibg=#12141E
        hi FloatermBorder guifg=#c29df1
        ]])
	end,
}
