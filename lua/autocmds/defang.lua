-- ~/.config/nvim/lua/autocmds/defang.lua

-- Manual command to defang the current buffer
vim.api.nvim_create_user_command("Defang", function()
	local bufnr = vim.api.nvim_get_current_buf()
	local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
	local content = table.concat(lines, "\n")

	local output = vim.fn.system({
		"python3",
		vim.fn.expand("~/.config/nvim/scripts/defanger/defanger.py"),
	}, content)

	if vim.v.shell_error ~= 0 then
		vim.notify("Error: defanger.py encountered an error.", vim.log.levels.ERROR)
		return
	end

	vim.schedule(function()
		vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
	end)
end, {})

-- Manual command to refang the current buffer
vim.api.nvim_create_user_command("Refang", function()
	local bufnr = vim.api.nvim_get_current_buf()
	local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
	local content = table.concat(lines, "\n")

	local output = vim.fn.system({
		"python3",
		vim.fn.expand("~/.config/nvim/scripts/defanger/defanger.py"),
		"--refang",
	}, content)

	if vim.v.shell_error ~= 0 then
		vim.notify("Error: defanger.py encountered an error.", vim.log.levels.ERROR)
		return
	end

	vim.schedule(function()
		vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
	end)
end, {})
