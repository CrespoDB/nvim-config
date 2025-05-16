return {
	"nvim-lualine/lualine.nvim",
	config = function()
		require("lualine").setup({
			options = {
				theme = "dracula",
			},
			sections = {
				lualine_a = { "mode" },
				lualine_b = { "branch" },
				lualine_c = {
					"filename",
					function()
						if not _G.investigation_start then
							return ""
						end
						-- custom investigation timer @autocmds/ticket.lua
						local elapsed = os.difftime(os.time(), _G.investigation_start)
						local mins = math.floor(elapsed / 60)
						local secs = elapsed % 60
						return string.format("⏱ %02dm:%02ds", mins, secs)
					end,
				},
				lualine_x = { "encoding", "fileformat", "filetype" },
				lualine_y = { "progress" },
				lualine_z = { "location" },
			},
		})
	end,
}
