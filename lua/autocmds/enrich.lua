local M = {}

function M.setup()
	vim.api.nvim_create_user_command("Enrich", function()
		-- Get buffer contents
		local bufnr = vim.api.nvim_get_current_buf()
		local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
		local content = table.concat(lines, "\n")

		-- Check if the 'enricher' command is available in the PATH
		if vim.fn.executable("enricher") == 0 then
			vim.notify(
				"enricher command not found. Please ensure pipx installed defanger is in your PATH.",
				vim.log.levels.ERROR
			)
			return
		end

		-- Call the pipx-installed enricher command synchronously
		local output = vim.fn.system({ "enricher" }, content)
		if vim.v.shell_error ~= 0 then
			vim.notify("Error: enricher encountered an issue.", vim.log.levels.ERROR)
			return
		end

		-- Prepare enriched output
		local content_lines = vim.split(output, "\n")
		table.insert(content_lines, 1, "")
		table.insert(content_lines, 1, "=== IOC ENRICHMENT RESULTS ===")

		-- Calculate maximum line length
		local max_line_len = 0
		for _, line in ipairs(content_lines) do
			max_line_len = math.max(max_line_len, #line)
		end

		local height = math.min(#content_lines, math.floor(vim.o.lines * 0.6))
		local width = math.min(max_line_len + 4, math.floor(vim.o.columns * 0.8))
		local row = math.floor((vim.o.lines - height) / 2)
		local col = math.floor((vim.o.columns - width) / 2)

		-- Create floating buffer and set content
		local float_buf = vim.api.nvim_create_buf(false, true)
		vim.api.nvim_buf_set_lines(float_buf, 0, -1, false, content_lines)
		vim.api.nvim_buf_set_option(float_buf, "filetype", "ioc_enrichment")

		-- Add highlights based on line patterns
		for i, line in ipairs(content_lines) do
			if line:match("^%[%+%]") then
				vim.api.nvim_buf_add_highlight(float_buf, -1, "DiffAdd", i - 1, 0, -1)
			elseif line:match("^%[%-%]") then
				vim.api.nvim_buf_add_highlight(float_buf, -1, "DiffDelete", i - 1, 0, -1)
			elseif line:match("^%[i%]") then
				vim.api.nvim_buf_add_highlight(float_buf, -1, "Comment", i - 1, 0, -1)
			end
		end

		-- Open floating window
		local win = vim.api.nvim_open_win(float_buf, true, {
			relative = "editor",
			row = row,
			col = col,
			width = width,
			height = height,
			style = "minimal",
			border = "rounded",
		})

		-- Set buffer-local keymaps using vim.keymap.set
		vim.keymap.set(
			"n",
			"q",
			":bd!<CR>",
			{ buffer = float_buf, silent = true, noremap = true, desc = "Close window" }
		)
		vim.keymap.set(
			"n",
			"<Esc>",
			":bd!<CR>",
			{ buffer = float_buf, silent = true, noremap = true, desc = "Close window" }
		)
		vim.keymap.set("n", "s", function()
			vim.cmd("w! ~/ioc_enrichment_report.txt")
		end, { buffer = float_buf, silent = true, noremap = true, desc = "Save report" })
		vim.keymap.set("n", "<C-d>", "<C-d>", { buffer = float_buf, silent = true, noremap = true })
		vim.keymap.set("n", "<C-u>", "<C-u>", { buffer = float_buf, silent = true, noremap = true })
	end, { desc = "Enrich current buffer IOCs via AbuseIPDB + VT" })

	vim.keymap.set("n", "<leader>e", ":Enrich<CR>", {
		noremap = true,
		silent = true,
		desc = "Run IOC Enrichment",
	})
end

return M
