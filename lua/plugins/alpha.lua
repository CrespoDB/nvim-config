--- @type LazyPluginSpec
return {
  "goolord/alpha-nvim",
  event = "VimEnter",
  dependencies = { "nvim-tree/nvim-web-devicons" },
  opts = function()
    local dashboard = require("alpha.themes.dashboard")
    require("alpha.term")
    local arttoggle = false

    local logo = {
      [[                                                    ]],
      [[ ███╗   ██╗███████╗ ██████╗ ██╗   ██╗██╗███╗   ███╗ ]],
      [[ ████╗  ██║██╔════╝██╔═══██╗██║   ██║██║████╗ ████║ ]],
      [[ ██╔██╗ ██║█████╗  ██║   ██║██║   ██║██║██╔████╔██║ ]],
      [[ ██║╚██╗██║██╔══╝  ██║   ██║╚██╗ ██╔╝██║██║╚██╔╝██║ ]],
      [[ ██║ ╚████║███████╗╚██████╔╝ ╚████╔╝ ██║██║ ╚═╝ ██║ ]],
      [[ ╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═══╝  ╚═╝╚═╝     ╚═╝ ]],
      [[                                                    ]],
    }

    local art = {
      -- { name, width, height }
      { "tohru", 62, 17 },
    }

    if arttoggle == true then
      dashboard.opts.opts.noautocmd = true
      dashboard.section.terminal.opts.redraw = true
      local path = vim.fn.stdpath("config") .. "/assets/"
      -- local random = math.random(1, #art)
      local currentart = art[1]
      dashboard.section.terminal.command = "cat " .. path .. currentart[1]

      dashboard.section.terminal.width = currentart[2]
      dashboard.section.terminal.height = currentart[3]

      dashboard.opts.layout = {
        dashboard.section.terminal,
        { type = "padding", val = 2 },
        dashboard.section.buttons,
        dashboard.section.footer,
      }
    else
      dashboard.section.header.val = logo
    end
    dashboard.section.buttons.val = {
      -- dashboard.button("SPC j", "󰈚 Restore Session", ":SessionRestore<cr>"),
      dashboard.button("e", " New file", ":ene <BAR> startinsert <CR>"),
      dashboard.button("f", " Find file", ":Telescope find_files<CR>"),
      dashboard.button("g", "󰱼 Find word", ":Telescope live_grep<CR>"),
      dashboard.button("r", " Recent", ":Telescope oldfiles<CR>"),
      dashboard.button("c", " Config", ":e $MYVIMRC <CR>"),
      dashboard.button("m", "󱌣 Mason", ":Mason<CR>"),
      dashboard.button("l", "󰒲 Lazy", ":Lazy<CR>"),
      dashboard.button("u", "󰂖 Update plugins", "<cmd>lua require('lazy').sync()<CR>"),
      dashboard.button("q", " Quit NVIM", ":qa<CR>"),
    }
    for _, button in ipairs(dashboard.section.buttons.val) do
      button.opts.hl = "AlphaButtons"
      button.opts.hl_shortcut = "AlphaShortcut"
    end
    dashboard.section.header.opts.hl = "Function"
    dashboard.section.buttons.opts.hl = "Identifier"
    dashboard.section.footer.opts.hl = "Function"
    dashboard.opts.layout[1].val = 4
    return dashboard
  end,
  config = function(_, dashboard)
    if vim.o.filetype == "lazy" then
      vim.cmd.close()
      vim.api.nvim_create_autocmd("User", {
        pattern = "AlphaReady",
        callback = function()
          require("lazy").show()
        end,
      })
    end

    local function getGreetingMessage()
      local hour = tonumber(os.date("%H"))
      local greeting = "Good day" -- Default greeting

      -- Determine part of the day
      if hour < 12 then
        greeting = "Good morning ☕"
      elseif hour >= 12 and hour < 18 then
        greeting = "Good afternoon 🧋"
      else
        greeting = "Good evening 🍵"
      end
      return greeting
    end

    require("alpha").setup(dashboard.opts)
    vim.api.nvim_create_autocmd("User", {
      pattern = "LazyVimStarted",
      callback = function()
        local v = vim.version()
        local dev = ""
        if v.prerelease == "dev" then
          dev = "-dev+" .. v.build
        else
          dev = ""
        end

        local version = v.major .. "." .. v.minor .. "." .. v.patch .. dev
        local stats = require("lazy").stats()
        local plugins_count = stats.loaded .. "/" .. stats.count
        local ms = math.floor(stats.startuptime + 0.5)
        local time = vim.fn.strftime("%H:%M:%S")
        local date = vim.fn.strftime("%d.%m.%Y")
        local line1 = " " .. plugins_count .. " plugins loaded in " .. ms .. "ms"
        local line2 = "󰃭 " .. date .. "  " .. time
        local line3 = " " .. version
        local line4 = getGreetingMessage()

        local line1_width = vim.fn.strdisplaywidth(line1)
        local line2Padded = string.rep(" ", (line1_width - vim.fn.strdisplaywidth(line2)) / 2) .. line2
        local line3Padded = string.rep(" ", (line1_width - vim.fn.strdisplaywidth(line3)) / 2) .. line3
        local line4Padded = string.rep(" ", (line1_width - vim.fn.strdisplaywidth(line4)) / 2) .. line4

        dashboard.section.footer.val = {
          line1,
          line2Padded,
          line3Padded,
          line4Padded,
        }
        pcall(vim.cmd.AlphaRedraw)
      end,
    })
  end,
}
