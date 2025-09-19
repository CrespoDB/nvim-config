vim.api.nvim_create_user_command("Daily", function()
  local daily_dir = "~/notes/daily"
  local date_str = os.date("%Y-%m-%d")
  local file_path = string.format("%s/%s.md", daily_dir, date_str)

  -- Frontmatter template
  local template = string.format(
    [[
---
id: daily-%s
title: "Daily – %s"
tags: [daily]
date: %s
---

## ✅ To‑Do
- [ ]

## 📓 Notes
-

]],
    date_str,
    date_str,
    date_str
  )

  -- Create file if it doesn't exist
  local expanded = vim.fn.expand(file_path)
  if vim.fn.filereadable(expanded) == 0 then
    vim.fn.writefile(vim.fn.split(template, "\n"), expanded)
  end

  vim.cmd("edit " .. file_path)
end, {})
