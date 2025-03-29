return {
  "epwalsh/obsidian.nvim",
  version = "*",
  ft = "markdown",
  opts = {
    workspaces = {
      {
        name = "vault",
        path = "~/notes", -- your vault path
      },
    },
    ui = {
      enable = false, -- render-markdown does ui
    },
    completion = {
      nvim_cmp = true,
      min_chars = 2,
    },
    new_notes_location = "current_dir",
    follow_url_func = function(url)
      vim.fn.jobstart({ "xdg-open", url }) -- works on Linux
    end,
  },
}
