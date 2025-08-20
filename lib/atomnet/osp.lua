-- OSP, Ordered Stream Protocol
-- The final step in mimicking TCP/TLS
-- The complete stack is OSP -> RCPS -> RCP -> AtomNET -> network hardware
-- Can be used for things like IRC, HTTP, or more importantly, AWP.

--[[

// big endian

struct osp_packet {
	uint32_t totalLen; // total length of entire write group
	uint32_t offset; // offset within write group, for sorting
	uint16_t len;
	uint8_t data[len];
};

]]

local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local event = require("event")

---@class osp.stream
---@field id string
---@field data any
---@field session rcps.session
---@field readBuffer string
---@field pendingReadBufferSize integer
---@field pendingReadBuffer {off: integer, data: string}[]
local stream = {}
stream.__index = stream

---@param session rcps.session
---@return osp.stream
--- Creates a new OSP stream from a raw RCPS connection.
--- This function is almost never useful, as the RCPS connection
--- still needs to encode its packets in OSP format.
--- This should only be used for protocol switching on the same connection.
function stream.new(session)
	return setmetatable({
		id = atomnet.randomPacketID(),
		session = session,
		readBuffer = "",
		pendingReadBufferSize = 0,
		pendingReadBuffer = {},
	}, stream)
end

---@param packet string
function stream:_unsafe_handlePacket(packet)
	local totalLen, off, len = string.unpack(">I4>I4>I2", packet)
	local data = packet:sub(11, 10 + len)
	self:_unsafe_addPending(totalLen, off, data)
end

---@param totalLen integer
---@param off integer
---@param data string
function stream:_unsafe_addPending(totalLen, off, data)
	table.insert(self.pendingReadBuffer, {
		off = off,
		data = data,
	})
	self.pendingReadBufferSize = self.pendingReadBufferSize + #data
	if self.pendingReadBufferSize >= totalLen then
		self:_unsafe_flushPending()
	end
end

function stream:_unsafe_flushPending()
	table.sort(self.pendingReadBuffer, function(a, b)
		return a.off < b.off
	end)

	for _, buffer in ipairs(self.pendingReadBuffer) do
		self.readBuffer = self.readBuffer .. buffer.data
	end

	self.pendingReadBuffer = {}
	self.pendingReadBufferSize = 0
	event.push("osp_data", self.id)
end

-- It does not simply return whether the connection is currently closed,
-- but rather if the buffer is fully read AND the connection is closed.
-- This effectively means it checks if the stream has ended.
function stream:isClosed()
	return #self.readBuffer == 0 and self:isDisconnected()
end

-- Returns whether the stream is disconnected.
-- This means writes would fail, but reads may succeed as there may still
-- be data left in the buffer.
function stream:isDisconnected()
	return self.session.state == "closed"
end

function stream:getBufferSize()
	return #self.readBuffer
end

---@param n integer
---@return string?
function stream:read(n)
	if self:isClosed() then return end
	while true do
		if #self.readBuffer >= n then
			local buf = self.readBuffer:sub(1, n)
			self.readBuffer = self.readBuffer:sub(n+1)
			return buf
		end
		if self:isDisconnected() then -- no possibility for more data
			local buf = self.readBuffer
			self.readBuffer = ""
			return buf
		end
		local e = event.pull()
		if e == "interrupted" then
			error("interrupted")
		end
	end
end

--- Reads until a specific byte, and consumes said byte.
---@param c string
---@return string?
function stream:readUntil(c)
	if self:isClosed() then return end
	local i = 1
	while true do
		-- we scan with i to prevent re-scanning parts that we already checked for
		local j = string.find(self.readBuffer, c, i, true)
		if j then
			local buf = self.readBuffer:sub(1, j-1)
			self.readBuffer = self.readBuffer:sub(j+1)
			return buf
		end
		i = #self.readBuffer+1 -- we skip over the entire length of the buffer since we scanned it
		if self:isDisconnected() then -- no possibility for more data
			local buf = self.readBuffer
			self.readBuffer = ""
			return buf
		end
		local e = event.pull()
		if e == "interrupted" then
			error("interrupted")
		end
	end
end

function stream:readLine()
	return self:readUntil("\n")
end

function stream:readCString()
	return self:readUntil("\0")
end

---@param data string
---@param blockSize? integer
function stream:write(data, blockSize)
	if self:isClosed() then return end

	blockSize = blockSize or 4096
	assert(blockSize <= 65535, "invalid blocksize") -- u16 limit

	-- TODO: write in parallel to increase bandwidth and benefit from the OSP protocol's ordering guarantees

	local off = 0
	while off < #data do
		local chunk = string.sub(data, off+1, off+blockSize)
		local packet = string.pack(">I4>I4>I2", #data, off, #chunk) .. chunk
		assert(rcps.send(self.session, packet))
		off = off + #chunk
	end
end

function stream:disconnect()
	rcps.disconnect(self.session, rcps.exit.closed, "")
	-- cleans up memory faster
	self.pendingReadBuffer = {}
	self.pendingReadBufferSize = 0
end

function stream:close()
	self:disconnect()
	self.readBuffer = "" -- stops reading
end

local osp = {}

---@type rcps.vtable
local _CLIENT_VTABLE = {
	connected = function (sesh, encryption)
		sesh.data = stream.new(sesh)
	end,
	disconnected = function (sesh, exitCode, msg)
		---@type osp.stream
		local s = sesh.data
		s:disconnect()
	end,
	timeout = function (sesh, packetID)
		---@type osp.stream
		local s = sesh.data
		s:disconnect()
	end,
	responded = function (sesh, packetID, accepted, response)
		---@type osp.stream
		local s = sesh.data
		if not accepted then s:disconnect() end
	end,
	sent = function (sesh, data)
		---@type osp.stream
		local s = sesh.data
		s:_unsafe_handlePacket(data)
		return true, ""
	end,
}

---@param address atomnet.address
---@param port integer
---@param timeout? number
---@param connectOpts? rcps.connectOpts
---@return osp.stream?
function osp.connectSync(address, port, timeout, connectOpts)
	timeout = timeout or 5
	local conn = rcps.connectSync(address, port, _CLIENT_VTABLE, timeout, connectOpts)
	if not conn then
		return
	end
	return conn.data
end

---@alias osp.serverCallback fun(stream: osp.stream)

---@param port? integer
---@param callback osp.serverCallback
---@param keys? rcps.serverKeys
---@return integer
function osp.open(port, callback, keys)
	---@type rcps.vtable
	local _SRVR_VTABLE = {
		connected = function (sesh, encryption)
			local s = stream.new(sesh)
			sesh.data = s
			callback(s)
		end,
		disconnected = function (sesh, exitCode, msg)
			---@type osp.stream
			local s = sesh.data
			s:disconnect()
		end,
		timeout = function (sesh, packetID)
			---@type osp.stream
			local s = sesh.data
			s:disconnect()
		end,
		responded = function (sesh, packetID, accepted, response)
			---@type osp.stream
			local s = sesh.data
			if not accepted then s:disconnect() end
		end,
		sent = function (sesh, data)
			---@type osp.stream
			local s = sesh.data
			s:_unsafe_handlePacket(data)
			return true, ""
		end,
	}

	return rcps.open(port, _SRVR_VTABLE, keys)
end

---@param port integer
function osp.close(port)
	rcps.close(port)
end

return osp
