return {
	"epwalsh/obsidian.nvim",
	version = "*",
	lazy = true,
	event = {
		"BufReadPre " .. vim.fn.expand("~/notes") .. "/*.md",
		"BufNewFile " .. vim.fn.expand("~/notes") .. "/*.md",
	},
	dependencies = {
		"nvim-lua/plenary.nvim",
	},
	opts = {
		workspaces = {
			{
				name = "vault",
				path = vim.fn.expand("~/notes"),
			},
		},
		ui = {
			enable = false, -- using render-markdown instead.
		},
		completion = {
			nvim_cmp = true,
			min_chars = 2,
		},
		new_notes_location = "current_dir",
		follow_url_func = function(url)
			vim.fn.jobstart({ "xdg-open", url })
		end,
		templates = {
			subdir = "templates",
		},
	},
	config = function(_, opts)
		require("obsidian").setup(opts)
		-- custom ticket commands [[cmds]]
		require("cmds.ticket").setup()
	end,
}
