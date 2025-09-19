local M = {}

function M.setup()
  -- Try to find the pipx-installed mdr-parse in PATH
  local mdr_parse_cmd = vim.fn.exepath("mdr-parse")
  if mdr_parse_cmd == "" then
    -- Fallback to explicit path if exepath fails; adjust as needed
    mdr_parse_cmd = os.getenv("HOME") .. "/.local/bin/mdr-parse"
  end

  if vim.fn.filereadable(mdr_parse_cmd) == 0 then
    vim.notify("mdr-parse not found at: " .. mdr_parse_cmd, vim.log.levels.ERROR)
    return
  end

  -- Helper function to get visual selection
  local function get_visual_selection()
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    
    local start_row = start_pos[2] - 1
    local start_col = start_pos[3] - 1
    local end_row = end_pos[2] - 1
    local end_col = end_pos[3]
    
    local lines = vim.api.nvim_buf_get_lines(0, start_row, end_row + 1, false)
    
    if #lines == 0 then
      return ""
    end
    
    -- Handle single line selection
    if #lines == 1 then
      return lines[1]:sub(start_col + 1, end_col)
    end
    
    -- Handle multi-line selection
    lines[1] = lines[1]:sub(start_col + 1)
    lines[#lines] = lines[#lines]:sub(1, end_col)
    
    return table.concat(lines, "\n")
  end

  -- Helper function to replace visual selection
  local function replace_visual_selection(new_text)
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    
    local start_row = start_pos[2] - 1
    local start_col = start_pos[3] - 1
    local end_row = end_pos[2] - 1
    local end_col = end_pos[3]
    
    local new_lines = vim.split(new_text, "\n")
    
    -- Replace the selected text
    vim.api.nvim_buf_set_text(0, start_row, start_col, end_row, end_col, new_lines)
  end

  -- Parse visual selection command
  vim.api.nvim_create_user_command("MDRParseSelection", function()
    local selection = get_visual_selection()
    
    if selection == "" then
      vim.notify("No text selected", vim.log.levels.WARN)
      return
    end

    local output = vim.fn.system({ mdr_parse_cmd }, selection)
    if vim.v.shell_error ~= 0 then
      vim.notify("mdr-parse failed: " .. vim.v.shell_error, vim.log.levels.ERROR)
      return
    end

    -- Remove trailing newline if present
    output = output:gsub("\n$", "")
    
    replace_visual_selection(output)
    vim.notify("MDR entity data parsed successfully", vim.log.levels.INFO)
  end, { 
    desc = "Parse MDR entity data in visual selection",
    range = true 
  })

  -- Set up keymap for visual selection parsing
  vim.keymap.set('v', 'gm', function()
    vim.cmd('MDRParseSelection')
  end, { desc = 'Parse MDR entity selection' })
end

return M