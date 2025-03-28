-- ~/.config/nvim/lua/autocmds/defang.lua
-- This autocommand uses the "defanger" command to process text files on save.

-- Automatic defanging on save for .txt and .md files
vim.api.nvim_create_autocmd("BufWritePre", {
	pattern = { "*.txt", "*.md" },
	callback = function()
		local bufnr = vim.api.nvim_get_current_buf()
		local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
		local content = table.concat(lines, "\n")

		-- Call defanger (default is defang mode)
		local output = vim.fn.system("defanger", content)
		if vim.v.shell_error ~= 0 then
			vim.notify("Error: defanger encountered an error.", vim.log.levels.ERROR)
			return
		end
		vim.schedule(function()
			vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
		end)
	end,
})

-- Manual command to defang the current buffer
vim.api.nvim_create_user_command("Defang", function()
	local bufnr = vim.api.nvim_get_current_buf()
	local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
	local content = table.concat(lines, "\n")

	local output = vim.fn.system("defanger", content)
	if vim.v.shell_error ~= 0 then
		vim.notify("Error: defanger encountered an error.", vim.log.levels.ERROR)
		return
	end

	vim.schedule(function()
		vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
	end)
end, {})

-- Manual command to refang the current buffer (i.e., revert changes)
vim.api.nvim_create_user_command("Refang", function()
	local bufnr = vim.api.nvim_get_current_buf()
	local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
	local content = table.concat(lines, "\n")

	local output = vim.fn.system("defanger --refang", content)
	if vim.v.shell_error ~= 0 then
		vim.notify("Error: defanger encountered an error.", vim.log.levels.ERROR)
		return
	end

	vim.schedule(function()
		vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
	end)
end, {})
