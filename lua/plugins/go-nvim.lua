return {
	"ray-x/go.nvim",
	dependencies = {
		"ray-x/guihua.lua", -- Required by go.nvim for UI components
	},
	config = function()
		require("go").setup() -- Setup with default configurations
	end,
	event = "BufReadPre", -- Consider loading on buffer read for Go files
	ft = { "go", "gomod" },
	build = ':lua require("go.install").update_all_sync()', -- Optional: install/update Go binaries
}
