-- Manual command to defang the current buffer using the globally installed "defanger" command
vim.api.nvim_create_user_command("Defang", function()
  local bufnr = vim.api.nvim_get_current_buf()
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local content = table.concat(lines, "\n")

  local output = vim.fn.system({ "defanger" }, content)

  if vim.v.shell_error ~= 0 then
    vim.notify("Shell error: " .. tostring(vim.v.shell_error), vim.log.levels.ERROR)
    return
  end

  vim.schedule(function()
    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
  end)
end, {})

-- Manual command to refang the current buffer using the globally installed "defanger" command with the "--refang" flag
vim.api.nvim_create_user_command("Refang", function()
  local bufnr = vim.api.nvim_get_current_buf()
  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local content = table.concat(lines, "\n")

  local output = vim.fn.system({ "defanger", "--refang" }, content)

  if vim.v.shell_error ~= 0 then
    vim.notify("Error: defanger encountered an error.", vim.log.levels.ERROR)
    return
  end

  vim.schedule(function()
    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
  end)
end, {})
