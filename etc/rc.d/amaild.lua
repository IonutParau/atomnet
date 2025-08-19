-- Atomic Mail Daemon, powered by AtomNET RCP sessions
-- Comms happens on port 25 over RCP
-- AMail is very basic, pure-text mail. It does not allow file sharing or MIMEs.
-- The address can be a resolvable host.
-- The EMAILER is NOT supposed to send the address, instead, the IP of the sender is shown!
--[[

// Big endian!

// When establishing a connection
struct amail_newmail {
	uint8_t magic = 0;
	// all are null-terminated
	char subject[];
	char emailer[];
	char emailee[];
};

struct amail_sendmail {
	uint8_t magic = 1;
	uint16_t orderIndex; // should be in increasing order
	char packet[]; // NULL-terminated
};

struct amail_closemail {
	uint8_t magic = 2;
};

// RCP rejected would contain error message to be displayed

// if a session is closed without closemail being sent, the mail should be
// discarded

]]
-- When mail is displayed, it is assumed that the file is named <Emailer>: <Subject>.

-- Folder structure: /var/amail/<server IP>/<mail>.
-- This is for mail you got! For mail you sent, you should keep it somewhere!
-- By default, the mail client will check if a file exists and if it doesn't let you write it.

local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local event = require("event")
local fs = require("filesystem")
local component = require("component")
local computer = require("computer")

local function log(fmt, ...)
	local s = string.format(fmt, ...)

	if component.isAvailable("ocelot") then
		component.ocelot.log(s)
	end
end

local mailPort = 25

local root = "/var/amail"

---@class amaild.chunk
---@field data string
---@field order integer

---@class amaild.data
---@field subject string
---@field emailer string
---@field emailee string
---@field path string
---@field chunks amaild.chunk[]

---@class amaild.connectionData
---@field conn rcps.session
---@field heartbeatDeadline number

---@return number
local function nextHeartbeatDeadline()
	return computer.uptime() + 3
end

---@type amaild.connectionData[]
local conns = {}

---@param conn rcps.session
local function gotHeartbeat(conn)
	for _, c in ipairs(conns) do
		if c.conn == conn then
			c.heartbeatDeadline = nextHeartbeatDeadline()
			break
		end
	end
end

local function timer()
	local now = computer.uptime()
	for i=#conns, 1, -1 do
		if conns[i].heartbeatDeadline <= now then
			table.remove(conns, i)
			rcps.disconnect(conns[i].conn, rcps.exit.timeout, "missing heartbeat")
			break
		end
	end
end

---@type rcps.vtable
local mailVtable = {
	connected = function(conn, encryption)
		log("%s connected", tostring(conn))
		---@type amaild.connectionData
		local data = {
			conn = conn,
			heartbeatDeadline = nextHeartbeatDeadline(),
		}
		table.insert(conns, data)
	end,
	disconnected = function (sesh, exitCode, msg)
		log("%s disconnected", tostring(sesh))
		for i=#conns, 1, -1 do
			if conns[i].conn == sesh then
				table.remove(conns, i)
				break
			end
		end
	end,
	sent = function (sesh, data)
		if data:byte(1, 1) == 0 then
			if sesh.data then return false, "duplicate connection" end
			local subject, emailer, emailee = string.unpack("zzz", data, 2)
			local dir = string.format("%s/%s", root, atomnet.formatAddress(sesh.src))
			fs.makeDirectory(dir)
			local path = string.format("%s/[%s] %s", dir, emailer, subject)
			log("Received mail %s", path)
			---@type amaild.data
			local seshData = {
				subject = subject,
				emailer = emailer,
				emailee = emailee,
				path = path,
				chunks = {},
			}
			sesh.data = seshData
			return true, ""
		end
		if data:byte(1, 1) == 1 then
			if not sesh.data then return false, "bad order" end
			gotHeartbeat(sesh)
			local order, packet = string.unpack(">I2z", data, 2)
			---@type amaild.chunk
			local chunk = {
				order = order,
				data = packet,
			}
			table.insert(sesh.data.chunks, chunk)
			return true, ""
		end
		if data:byte(1, 1) == 2 then
			if not sesh.data then return false, "bad order" end
			-- flush
			---@type amaild.data
			local stuff = sesh.data
			sesh.data = nil

			local f = assert(io.open(stuff.path, "w"))

			table.sort(stuff.chunks, function(a, b)
				return a.order < b.order
			end)

			f:write("Subject: ", stuff.subject, "\n")
			f:write("From: ", stuff.emailer, "\n")
			f:write("To: ", stuff.emailee, "\n")
			f:write("\n")

			for _, chunk in ipairs(stuff.chunks) do
				f:write(chunk.data)
			end

			f:close()
			computer.beep(500, 0.1)
			return true, ""
		end
		return false, ""
	end,
	-- we don't send anything so these don't matter
	timeout = function (sesh, packetID)
	end,
	responded = function (sesh, packetID, accepted, response)
	end,
}

local _TIMER

local function cleanup()
	rcps.close(mailPort)
	if _TIMER then
		event.cancel(_TIMER)
	end
end

function start()
	cleanup()
	rcps.open(mailPort, mailVtable)
	_TIMER = event.timer(0, timer, math.huge)

	fs.makeDirectory(root)
end

function stop()
	cleanup()
end

function list()
	print(#conns .. " connections")
	for _, conn in ipairs(conns) do
		local fmt = string.format("%s:%d", atomnet.formatAddress(conn.conn.src), conn.conn.srcPort)
		print(fmt)
	end
end
