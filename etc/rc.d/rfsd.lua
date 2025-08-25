local atomnet = require("atomnet")
local osp = require("atomnet.osp")
local rfs = require("atomnet.rfs")
local event = require("event")
local fs = require("filesystem")
local shell = require("shell")
local computer = require("computer")

local timeoutPerPacket = 5*60
local sessionDeadline = 15*60

---@class rfsd.restriction
---@field path string
---@field reading? boolean
---@field writing? boolean
---@field deleting? boolean

---@class rfsd.user
---@field root string
---@field restrictions rfsd.restriction[]

---@param restrictions rfsd.restriction[]
local function sortRestrictions(restrictions)
	table.sort(restrictions, function(a, b)
		return #a.path > #b.path
	end)
end

---@param path string
---@return string
local function canonical(path)
	local p = fs.canonical(path)
	if p:sub(1, 1) == "/" then return p end
	return "/" .. p
end

---@param root string
---@param path string
---@return string
local function resolve(root, path)
	path = canonical(path)
	if root == "/" then
		return path
	else
		return ((root .. path):gsub("//", "/"))
	end
end

---@param restrictions rfsd.restriction[]
---@param path string
---@return boolean
local function canWrite(restrictions, path)
	sortRestrictions(restrictions)
	path = canonical(path)
	for _, restriction in ipairs(restrictions) do
		if restriction.writing ~= nil then
			if restriction.path == path then
				return restriction.writing
			end
			local prefix = restriction.path .. "/"
			if path:sub(1, #prefix) == prefix then
				return restriction.writing
			end
		end
	end
	return true
end

---@param restrictions rfsd.restriction[]
---@param path string
---@return boolean
local function canRead(restrictions, path)
	sortRestrictions(restrictions)
	path = canonical(path)
	for _, restriction in ipairs(restrictions) do
		if restriction.reading ~= nil then
			if restriction.path == path then
				return restriction.reading
			end
			local prefix = restriction.path .. "/"
			if path:sub(1, #prefix) == prefix then
				return restriction.reading
			end
		end
	end
	return true
end

---@param restrictions rfsd.restriction[]
---@param path string
---@return boolean
local function canDelete(restrictions, path)
	sortRestrictions(restrictions)
	path = canonical(path)
	for _, restriction in ipairs(restrictions) do
		if restriction.deleting ~= nil then
			if restriction.path == path then
				return restriction.deleting
			end
			local prefix = restriction.path .. "/"
			if path:sub(1, #prefix) == prefix then
				return restriction.deleting
			end
		end
	end
	return true
end

---@class rfsd.session
---@field user string
---@field deadline number

---@class rfsd.connection
---@field timeout number
---@field stream osp.stream
---@field oldPacketCount integer
---@field state? string
---@field data table

---@type table<string, rfsd.user>
local users = {}

---@type table<string, rfsd.session>
local sessions = {}

---@type rfsd.connection[]
local connections = {}

---@type table
local t = _ENV

function t.addUser(...)
	local args, opts = shell.parse(...)
	local name, root = args[1], args[2]
	assert(name, "no name")
	assert(root, "no root")

	if users[name] then
		error("duplicate user")
	end

	users[name] = {
		root = canonical(root),
		restrictions = {},
		sessionCount = 0,
	}
end

function t.deleteUser(name)
	users[name] = nil
end

---@param restriction rfsd.restriction
---@return string
local function encodeRestriction(restriction)
	---@param d boolean?
	---@param allowed string
	local function permsDigit(d, allowed)
		if d == nil then return "?" end
		if d == false then return "-" end
		return allowed
	end
	return ""
		.. permsDigit(restriction.reading, "R")
		.. permsDigit(restriction.writing, "W")
		.. permsDigit(restriction.deleting, "D")
end

---@param path string
---@param s string
local function decodeRestriction(path, s)
	---@type rfsd.restriction
	local restriction = {path = path}
	---@return boolean?
	local function decodeDigit(i)
		if #s < i then return end
		if s:sub(i,i) == "?" then return end
		if s:sub(i,i) == "-" then return false end
		return true
	end
	restriction.reading = decodeDigit(1)
	restriction.writing = decodeDigit(2)
	restriction.deleting = decodeDigit(3)
	return restriction
end

function t.restrictionsOf(name)
	local user = assert(users[name], "no such user")
	if not user.restrictions[1] then
		print("No restrictions")
	end
	for _, restriction in ipairs(user.restrictions) do
		local fmt = string.format("%s %s", encodeRestriction(restriction), restriction.path)
		print(fmt)
	end
end

function t.restrictFor(name, path, restrictionStr)
	local user = assert(users[name], "no such user")
	assert(path, "no path given")
	assert(restrictionStr, "no path given")
	path = canonical(path)

	local restriction = decodeRestriction(path, restrictionStr)
	table.insert(user.restrictions, restriction)
	sortRestrictions(user.restrictions)
end

function t.removeRestriction(name, path)
	local user = assert(users[name], "no such user")
	assert(path, "no path given")
	path = canonical(path)

	for i=1,#user.restrictions do
		if user.restrictions[i] then
			table.remove(user.restrictions, i)
			return
		end
	end
end

function t.users()
	if not next(users) then
		print("No users")
	end
	for name, user in pairs(users) do
		print(string.format("%s %s", name, user.root))
	end
end

function t.sessions()
	if not next(sessions) then
		print("No sessions")
	end
	for id, session in pairs(sessions) do
		local now = computer.uptime()
		local fmt = string.format("%s %s (%.2fs left)", atomnet.hexdump(id), session.user, session.deadline - now)
		print(fmt)
	end
end

function t.killSession(id)
	sessions[id] = nil
end

function t.connections()
	if not next(connections) then
		print("No connections")
	end
	for _, conn in ipairs(connections) do
		local now = computer.uptime()
		local rcpsSesh = conn.stream.session
		local fmt = string.format("%s:%d (%.2fs until timeout)", atomnet.formatAddress(rcpsSesh.src), rcpsSesh.srcPort, conn.timeout - now)
		print(fmt)
	end
end

---@param user string
---@return string
local function makeSession(user)
	local id = ""
	for _=1,16 do
		id = id .. string.char(math.random(0, 255))
	end
	sessions[id] = {
		user = user,
		deadline = computer.uptime() + sessionDeadline,
	}
	return id
end

---@param connection rfsd.connection
local function processConnection(connection)
	local stream = connection.stream

	if stream.packetCount ~= connection.oldPacketCount then
		connection.oldPacketCount = stream.packetCount
		connection.timeout = computer.uptime() + timeoutPerPacket
	end

	if connection.state == nil then
		-- We're fucking parsing magic here
		if stream:getBufferSize() >= 2 then
			connection.state = stream:read(2)
		end
	end

	if connection.state == "NS" then
		if stream:getBufferSize() > 0 then
			connection.data.NS_auth = stream:read(1):byte()
			connection.state = "NS-auth"
		end
	end

	if connection.state == "NS-auth" then
		if stream:bufferHas('\0') then
			local user = stream:readCString()
			connection.state = nil

			if connection.data.NS_auth == rfs.authAlgorithm.NOPASS then
				if not users[user] then
					stream:writeAsync("ERno such user\0")
					return
				end

				local sesh = makeSession(user or "")
				stream:writeAsync("GR" .. sesh)
			else
				stream:close()
			end
		end
	end

	if connection.state == "MI" then
		if stream:getBufferSize() >= 16 then
			---@type string
			local sessionID = stream:read(16) or ""
			connection.state = nil

			local session = sessions[sessionID]
			if not session then
				stream:writeAsync("ERbad session ID\0")
				return
			end

			stream:writeAsync("GR" .. session.user .. "\0")
			return
		end
	end

	if connection.state == "LS" then
		if stream:getBufferSize() >= 16 then
			connection.data.session = stream:read(16)
			connection.state = "LS-path"
		end
	end

	if connection.state == "LS-path" then
		if stream:bufferHas('\0') then
			local path = canonical(stream:readCString() or "/")
			connection.state = nil

			local session = sessions[connection.data.session]
			if not session then
				stream:writeAsync("ERbad session ID\0")
				return
			end

			local user = users[session.user]
			if not user then
				stream:writeAsync("ERuser is dead\0")
				return
			end

			if not canRead(user.restrictions, path) then
				stream:writeAsync("ERpermission denied\0")
				return
			end

			local list = {}
			for entry in fs.list(resolve(user.root, path)) do
				table.insert(list, entry)
			end

			stream:writeAsync("GR" .. string.pack(">I2", #list))
			local buf = ""
			for _, entry in ipairs(list) do
				buf = buf .. entry .. "\0"
			end
			stream:writeAsync(buf)
			return
		end
	end

	if connection.state == "DF" then
		if stream:getBufferSize() >= 16 then
			connection.data.session = stream:read(16) or ""
			connection.state = "DF-path"
		end
	end

	if connection.state == "DF-path" then
		if stream:bufferHas('\0') then
			connection.data.path = stream:readCString() or ""
			connection.state = "DF-off"
		end
	end

	if connection.state == "DF-off" then
		if stream:getBufferSize() >= 8 then
			local off, len = string.unpack(">I4>I4", stream:read(8) or "")
			connection.state = nil

			local session = sessions[connection.data.session]
			if not session then
				stream:writeAsync("ERbad session ID\0")
				return
			end

			local user = users[session.user]
			if not user then
				stream:writeAsync("ERuser is dead\0")
				return
			end

			if not canRead(user.restrictions, connection.data.path) then
				stream:writeAsync("ERpermission denied\0")
				return
			end

			local realPath = resolve(user.root, connection.data.path)

			if not fs.exists(realPath) then
				stream:writeAsync("ERno such file\0")
				return
			end

			if fs.isDirectory(realPath) then
				stream:writeAsync("ERis a directory\0")
				return
			end

			local f, err = io.open(realPath, "rb")
			if not f then
				stream:writeAsync("ER" .. (err or "bad path") .. "\0")
				return
			end

			-- TODO: read lazily
			f:seek("set", off)
			local data = f:read(len == 0 and "a" or len)
			stream:writeAsync("GR" .. string.pack(">I4", #data) .. data)
			return
		end
	end
end

local function tick()
	for i=#connections, 1, -1 do
		local connection = connections[i]

		if computer.uptime() >= connection.timeout then
			table.remove(connections, i)
		elseif connection.stream:isClosed() then
			table.remove(connections, i)
		elseif connection.stream:writesPending() then
			-- do nothing, idk just idle
		else
			local ok, err = xpcall(processConnection, debug.traceback, connection)
			if not ok then
				print(err)
			end
		end
	end

	local sessionsToKill = {}

	for id, session in pairs(sessions) do
		if computer.uptime() >= session.deadline then
			table.insert(sessionsToKill, id)
		end
	end

	for _, id in ipairs(sessionsToKill) do
		sessions[id] = nil
	end
end

local _RFSD_TIMER = nil
function t.start()
	_RFSD_TIMER = event.timer(0, tick, math.huge)
	osp.open(rfs.port, function(s)
		---@type rfsd.connection
		local conn = {
			stream = s,
			timeout = computer.uptime() + sessionDeadline,
			oldPacketCount = 0,
			data = {},
		}
		table.insert(connections, conn)
	end)
end

function t.stop()
	event.cancel(_RFSD_TIMER)
	for _, conn in ipairs(connections) do
		conn.stream:disconnect()
	end
	osp.close(rfs.port)
end

function t.unload()
	t.stop()
	require("rc").loaded.rfsd = nil
end
