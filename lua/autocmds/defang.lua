local M = {}

function M.setup()
  -- Try to find the pipx-installed defanger in PATH
  local defanger_cmd = vim.fn.exepath("defanger")
  if defanger_cmd == "" then
    -- Fallback to explicit path if exepath fails; adjust as needed
    defanger_cmd = os.getenv("HOME") .. "/.local/bin/defanger"
  end

  if vim.fn.filereadable(defanger_cmd) == 0 then
    vim.notify("defanger not found at: " .. defanger_cmd, vim.log.levels.ERROR)
    return
  end

  -- Auto-defang on write for common IOC filetypes
  vim.api.nvim_create_autocmd("BufWritePre", {
    pattern = { "*.txt", "*.log", "*.ioc" },
    callback = function()
      local bufnr = vim.api.nvim_get_current_buf()
      local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
      local content = table.concat(lines, "\n")

      local output = vim.fn.system({ defanger_cmd }, content)
      if vim.v.shell_error ~= 0 then
        vim.notify("defanger failed: " .. vim.v.shell_error, vim.log.levels.ERROR)
        return
      end

      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
    end,
  })

  -- Manual commands
  vim.api.nvim_create_user_command("Defang", function()
    local bufnr = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local content = table.concat(lines, "\n")

    local output = vim.fn.system({ defanger_cmd }, content)
    if vim.v.shell_error ~= 0 then
      vim.notify("defanger failed: " .. vim.v.shell_error, vim.log.levels.ERROR)
      return
    end

    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
  end, { desc = "Defang IOCs in current buffer" })

  vim.api.nvim_create_user_command("Refang", function()
    local bufnr = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local content = table.concat(lines, "\n")

    local output = vim.fn.system({ defanger_cmd, "--refang" }, content)
    if vim.v.shell_error ~= 0 then
      vim.notify("defanger --refang failed: " .. vim.v.shell_error, vim.log.levels.ERROR)
      return
    end

    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, vim.split(output, "\n"))
  end, { desc = "Refang IOCs in current buffer" })
end

return M
