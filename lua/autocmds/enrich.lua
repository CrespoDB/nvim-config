local M = {}

local unpack = unpack or table.unpack

function M.setup()
  vim.api.nvim_create_user_command("Enrich", function()
    -- Get buffer contents
    local bufnr = vim.api.nvim_get_current_buf()
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local content = table.concat(lines, "\n")

    -- Call enricher script
    local output = vim.fn.system({
      "python3",
      vim.fn.expand("~/.config/nvim/scripts/defanger/enricher.py"),
    }, content)

    if vim.v.shell_error ~= 0 then
      vim.notify("Error: enricher.py encountered an issue.", vim.log.levels.ERROR)
      return
    end

    -- Prepare enriched output
    local content_lines = vim.split(output, "\n")
    table.insert(content_lines, 1, "")
    table.insert(content_lines, 1, "=== IOC ENRICHMENT RESULTS ===")

    local max_line_len = math.max(unpack(vim.tbl_map(function(line)
      return #line
    end, content_lines)))
    local height = math.min(#content_lines, math.floor(vim.o.lines * 0.6))
    local width = math.min(max_line_len + 4, math.floor(vim.o.columns * 0.8))
    local row = math.floor((vim.o.lines - height) / 2)
    local col = math.floor((vim.o.columns - width) / 2)

    -- Create buffer and set content
    local float_buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_lines(float_buf, 0, -1, false, content_lines)

    -- Add highlight
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
    vim.api.nvim_open_win(float_buf, true, {
      relative = "editor",
      row = row,
      col = col,
      width = width,
      height = height,
      style = "minimal",
      border = "rounded",
    })

    -- Keymaps inside floating window
    vim.api.nvim_buf_set_keymap(float_buf, "n", "q", ":bd!<CR>", { noremap = true, silent = true })
    vim.api.nvim_buf_set_keymap(float_buf, "n", "<Esc>", ":bd!<CR>", { noremap = true, silent = true })
    vim.api.nvim_buf_set_keymap(
      float_buf,
      "n",
      "s",
      [[:w! ~/ioc_enrichment_report.txt<CR>]],
      { noremap = true, silent = true }
    )
    vim.api.nvim_buf_set_keymap(float_buf, "n", "<C-d>", "<C-d>", { noremap = true, silent = true })
    vim.api.nvim_buf_set_keymap(float_buf, "n", "<C-u>", "<C-u>", { noremap = true, silent = true })
  end, { desc = "Enrich current buffer IOCs via AbuseIPDB + VT" })

  vim.keymap.set("n", "<leader>e", ":Enrich<CR>", {
    noremap = true,
    silent = true,
    desc = "Run IOC Enrichment",
  })
end

return M
