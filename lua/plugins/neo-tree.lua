return {
	"nvim-neo-tree/neo-tree.nvim",
	branch = "v3.x",
	dependencies = {
		"nvim-lua/plenary.nvim",
		"nvim-tree/nvim-web-devicons",
		"MunifTanjim/nui.nvim",
	},
	config = function()
		vim.keymap.set("n", "<C-n>", ":Neotree filesystem reveal toggle left<CR>", {})
		-- Focus or unfocus Neo-tree
		vim.api.nvim_set_keymap("n", "<Leader>nf", ":Neotree focus<CR>", { noremap = true, silent = true })
		-- Close Neo-tree using a different keybinding to avoid conflict
		vim.api.nvim_set_keymap("n", "<Leader>nx", ":Neotree close<CR>", { noremap = true, silent = true })

		-- Optional: Toggle Neo-tree
		vim.api.nvim_set_keymap("n", "<Leader>nt", ":Neotree toggle left<CR>", { noremap = true, silent = true })
	end,
}
