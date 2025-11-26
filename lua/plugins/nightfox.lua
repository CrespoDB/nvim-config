return {
	"EdenEast/nightfox.nvim",
	name = "nightfox",
	lazy = false,
	priority = 1001,
	config = function()
		require("nightfox").setup({
			options = { transparent = false },
		})
		vim.cmd.colorscheme("dayfox")
	end,
}
