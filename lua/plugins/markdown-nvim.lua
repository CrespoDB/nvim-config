return {
	"MeanderingProgrammer/render-markdown.nvim",
	ft = { "markdown" },
	config = function()
		require("render-markdown").setup({
			completions = {
				lsp = {
					enabled = true,
				},
			},
		})
	end,
}
