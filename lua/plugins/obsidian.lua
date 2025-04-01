return {
  "epwalsh/obsidian.nvim",
  version = "*",
  ft = "markdown",
  opts = {
    workspaces = {
      {
        name = "vault",
        path = "~/notes",
      },
    },
    ui = {
      enable = false, -- handled by render-markdown
    },
    completion = {
      nvim_cmp = true,
      min_chars = 2,
    },
    new_notes_location = "current_dir",
    follow_url_func = function(url)
      vim.fn.jobstart({ "xdg-open", url }) -- works on Linux
    end,
    templates = {
      subdir = "templates", -- references ~/notes/templates/
    },
  },
  config = function()
    require("cmds.ticket").setup()
  end,
}
