-- Atomic Mail client, used for sending mail

local shell = require("shell")
local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local fs = require("filesystem")

local args, opts = shell.parse(...)

local mailPort = tonumber(opts.port) or 25

if args[1] == "send" then
	local emailer = args[2]
	local emailee = args[3]
	local subject = args[4]

	assert(emailer, "no emailer")
	assert(emailee, "no emailee")
	assert(subject, "no subject")

	local path = args[5]
	if not path then
		path = os.tmpname()
	end

	if not fs.exists(path) then
		os.execute("edit " .. path)
	end

	local ok, _, user, serverAddrStr = string.find(emailee, "^([^@]+)@(.+)$")
	assert(ok, "bad emailee")

	local serverAddr = atomnet.resolveHostSync(serverAddrStr)

	local f = assert(io.open(path, "r"))

	local filesize = f:seek("end", 0)
	f:seek("set", 0)

	print("File size is " .. filesize .. " bytes")

	local blocksize = tonumber(opts.size) or 1024

	local encryption = rcps.encryption.none
	if not opts.unencrypted then
		if rcps.encryptionSupported(rcps.encryption.stdencrypt256) then
			encryption = rcps.encryption.stdencrypt256
		end

		if encryption == rcps.encryption.none then
			print("\x1b[33mWARNING: ENCRYPTION NOT SUPPORTED, MESSAGES MAY BE WIRETAPPED OR INTERCEPTED")
			print("PRESS ENTER TO CONTINUE")
			print("PRESS CTRL-C TO EXIT")
			print("PASS --unencrypted TO SUPPRESS WARNING\x1b[0m")
			local _ = io.read("l")
			if not _ then return end
		end
	end

	print("Connecting...")
	local conn = rcps.connectSync(serverAddr, mailPort, rcps.nothingTable, 5, {
		encryption = encryption,
	})
	if not conn then
		print("Connection failed")
		return
	end
	print("Connected")

	local total = 0
	local seq = 0

	local function theMailStuff()
		-- new mail
		assert(rcps.send(conn, string.char(0) .. string.pack("zzz", subject, emailer, user)))

		while true do
			local chunk = f:read(blocksize)
			if not chunk then break end
			total = total + #chunk
			local fmt = string.format("Uploading %dB (%3.2f%%)", #chunk, total / filesize * 100)
			print(fmt)
			assert(rcps.send(conn, string.char(1) .. string.pack(">I2z", seq, chunk)))
			seq = seq + 1
		end

		-- flush mail
		assert(rcps.send(conn, string.char(2)))
	end

	local ok, err = xpcall(theMailStuff, debug.traceback)
	if not ok then
		print("Error:", err)
		return 1
	end

	rcps.disconnect(conn, rcps.exit.closed, "")

	f:close()

	print("Done")

	return
end

print("invalid action")
return
