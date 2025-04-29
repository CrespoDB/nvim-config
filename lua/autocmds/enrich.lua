local M = {}

function M.setup()
	local enricher_cmd = vim.fn.exepath("enricher")
	if enricher_cmd == "" then
		enricher_cmd = os.getenv("HOME") .. "/.local/bin/enricher"
	end
	if vim.fn.filereadable(enricher_cmd) == 0 then
		vim.notify("enricher not found at: " .. enricher_cmd, vim.log.levels.ERROR)
		return
	end

	local function make_float()
		local width = math.floor(vim.o.columns * 0.8)
		local height = math.floor(vim.o.lines * 0.6)
		local row = math.floor((vim.o.lines - height) / 2)
		local col = math.floor((vim.o.columns - width) / 2)

		local buf = vim.api.nvim_create_buf(false, true)

		vim.api.nvim_open_win(buf, true, {
			relative = "editor",
			row = row,
			col = col,
			width = width,
			height = height,
			style = "minimal",
			border = "rounded",
		})

		vim.bo[buf].buftype = "nofile"
		vim.bo[buf].bufhidden = "wipe"
		vim.bo[buf].swapfile = false

		return buf
	end

	local function run_enrich()
		local bufnr = vim.api.nvim_get_current_buf()
		local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
		local content = table.concat(lines, "\n")

		local float_buf = make_float()

		-- Create a temp file and write the content
		local tmpfile = vim.fn.tempname() .. ".ioc"
		vim.fn.writefile(vim.split(content, "\n"), tmpfile)

		local term_job_id = vim.fn.termopen({ enricher_cmd, tmpfile }, {
			on_exit = function(_, _)
				vim.schedule(function()
					os.remove(tmpfile) -- cleanup temp file when done
				end)
			end,
		})
	end

	vim.api.nvim_create_user_command("Enrich", function()
		run_enrich()
	end, { desc = "IOC Enrich (floating terminal)" })

	vim.keymap.set("n", "<leader>e", ":Enrich<CR>", { noremap = true, silent = true })
end

return M
