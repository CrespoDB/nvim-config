return {
	"akinsho/bufferline.nvim",
	version = "*",
	lazy = false,
	dependencies = {
		"nvim-tree/nvim-web-devicons",
	},
	config = function()
		require("bufferline").setup({
			options = {
				mode = "buffers",
				diagnostics = "nvim_lsp",
				separator_style = "slant",
				show_buffer_close_icons = false,
				show_close_icon = false,
				always_show_bufferline = true,
			},
		})
		-- cycles a buffer
		vim.keymap.set("n", "<Tab>", "<Cmd>BufferLineCycleNext<CR>")
		-- cycles previous buffer
		vim.keymap.set("n", "<S-Tab>", "<Cmd>BufferLineCyclePrev<CR>")
		-- close current buffer
		vim.keymap.set("n", "<leader>bd", "<Cmd>bd<CR>", { desc = "Close buffer" })
		-- or pick one to close
		vim.keymap.set("n", "<leader>bc", "<Cmd>BufferLinePickClose<CR>", { desc = "Pick buffer to close" })
	end,
}
