local M = {}

function M.setup()
  vim.api.nvim_create_user_command("NewTicket", function()
    local date = os.date("%Y-%m-%d")
    local id = tostring(math.random(1000, 9999))
    local filename = string.format("%s-ticket-%s.md", date, id)
    local full_path = vim.fn.expand("~/notes/tickets/" .. filename)

    vim.fn.mkdir(vim.fn.expand("~/notes/tickets"), "p")
    vim.cmd("edit " .. full_path)

    local template_path = vim.fn.expand("~/notes/templates/ticket.md")
    if vim.fn.filereadable(template_path) == 0 then
      vim.notify("Ticket template not found", vim.log.levels.ERROR)
      return
    end

    local lines = vim.fn.readfile(template_path)
    vim.api.nvim_buf_set_lines(0, 0, -1, false, lines)
  end, { desc = "Create a new plain ticket note from template" })

  vim.api.nvim_create_user_command("InsertTemplate", function()
    local pickers = require("telescope.pickers")
    local finders = require("telescope.finders")
    local actions = require("telescope.actions")
    local action_state = require("telescope.actions.state")
    local conf = require("telescope.config").values
    local previewers = require("telescope.previewers")

    local template_dir = vim.fn.expand("~/notes/templates/alert-types")
    local filenames = vim.fn.readdir(template_dir)

    local entries = vim.tbl_map(function(name)
      local full_path = template_dir .. "/" .. name
      return {
        value = full_path,
        display = name,
        ordinal = name,
        path = full_path,
      }
    end, filenames)

    pickers
        .new({}, {
          prompt_title = "Insert Alert-Type Template",
          finder = finders.new_table({
            results = entries,
            entry_maker = function(entry)
              return entry
            end,
          }),
          sorter = conf.generic_sorter({}),
          previewer = previewers.cat.new({}),
          attach_mappings = function(prompt_bufnr, _)
            actions.select_default:replace(function(prompt_bufnr)
              actions.close(prompt_bufnr) -- Close the Telescope prompt first
              print("📦 Template selected!")

              local selection = action_state.get_selected_entry()
              if not selection then
                print("⚠️ No selection made.")
                return
              end

              local lines = vim.fn.readfile(selection.path)
              if not lines or vim.tbl_isempty(lines) then
                print("⚠️ Template is empty or unreadable.")
                return
              end

              print("📄 Template contents:")
              for _, l in ipairs(lines) do
                print(l)
              end

              local buf_lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
              print("📄 Buffer lines:")
              for i, l in ipairs(buf_lines) do
                print(i .. ": " .. l)
              end

              -- Find where to insert
              local entity_line = nil
              local found_entities = false
              for i, line in ipairs(buf_lines) do
                if found_entities and #line >= 5 then
                  print("✅ Found separator at line: " .. i)
                  entity_line = i
                  break
                end
                if line:match("^## Entities:?$") then
                  print("🔍 Found '## Entities' at line: " .. i)
                  found_entities = true
                end
              end

              if entity_line then
                print("🚀 Inserting at line: " .. entity_line + 1)
                vim.api.nvim_buf_set_lines(0, entity_line + 1, entity_line + 1, false, lines)
              else
                print("❌ Entities section not found or separator not detected.")
                vim.notify("## Entities section not found", vim.log.levels.WARN)
              end
            end)
            return true
          end,
        })
        :find()
  end, { desc = "Pick and insert a template under ## Entities" })

  vim.keymap.set("n", "<leader>l", ":InsertTemplate<CR>", { noremap = true, silent = true })
end

return M
