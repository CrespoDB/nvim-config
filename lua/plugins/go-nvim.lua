return {
	"ray-x/go.nvim",
	dependencies = {
		"ray-x/guihua.lua",
	},
	config = function()
		require("go").setup()
	end,
	event = "BufReadPre",
	ft = { "go", "gomod" },
	build = ':lua require("go.install").update_all_sync()',
}
