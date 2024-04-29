return {
  "nvimtools/none-ls.nvim",          -- Correct repository for none-ls
  config = function()
    local null_ls = require("null-ls") -- using the existing variable name as per your setup

    null_ls.setup({
      sources = {
        -- Existing formatting sources
        null_ls.builtins.formatting.stylua,
        null_ls.builtins.formatting.gofmt,
        -- Existing diagnostics source
        null_ls.builtins.diagnostics.golangci_lint.with({
          extra_args = { "--fast" },
        }),
        -- Adding C/C++ formatting
        null_ls.builtins.formatting.clang_format.with({
          extra_args = { "--style=llvm" }, -- Customize the style as needed
        }),
      },
    })

    -- Auto-format on save
    vim.api.nvim_create_autocmd("BufWritePre", {
      pattern = { "*.go", "*.lua", "*.c", "*.cpp" }, -- Include C and C++ files
      callback = function()
        vim.lsp.buf.format()
      end,
    })
    vim.keymap.set("n", "<leader>gf", vim.lsp.buf.format, {})
  end,
}
