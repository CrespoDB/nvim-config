return {
	"catppuccin/nvim",
	lazy = false,
	name = "catppuccin",
	priority = 1000,
	config = function()
		-- Setup catppuccin with transparent background support
		require("catppuccin").setup({
			transparent_background = true,
			-- Add any additional configuration options here
		})
		-- Applying the colorscheme
		vim.cmd.colorscheme("catppuccin")
	end,
}
