-- OSP, Ordered Stream Protocol
-- The final step in mimicking TCP/TLS
-- The complete stack is OSP -> RCPS -> RCP -> AtomNET -> network hardware
-- Can be used for things like IRC, HTTP, or more importantly, AWP.

--[[

// big endian

struct osp_packet {
	uint32_t offset; // offset within the socket, for ordering
	uint16_t len;
	uint8_t data[len];
};

]]

local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local event = require("event")

local osp = {}

osp.minimumCongestionWindow = 1
osp.maximumCongestionWindow = 4

---@class osp.stream
---@field id string
---@field data any
---@field session rcps.session
---@field readBuffer string
---@field currentOffset integer
---@field writingOffset integer
---@field pendingReadBuffer {off: integer, data: string}[]
---@field packetCount integer
---@field pendingWriteBuffer {data: string, blockSize: integer}[]
---@field pendingWritePacketsLeft integer
---@field congestionWindow integer
---@field packetsWereLost boolean
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
		currentOffset = 0,
		writingOffset = 0,
		pendingReadBuffer = {},
		packetCount = 0,
		pendingWriteBuffer = {},
		pendingWritePacketsLeft = 0,
		congestionWindow = osp.minimumCongestionWindow,
		packetsWereLost = false,
	}, stream)
end

---@param packet string
function stream:_unsafe_handlePacket(packet)
	self.packetCount = self.packetCount + 1
	local off, len = string.unpack(">I4>I2", packet)
	local data = packet:sub(7, 6 + len)
	self:_unsafe_addPending(off, data)
end

---@param off integer
---@param data string
function stream:_unsafe_addPending(off, data)
	table.insert(self.pendingReadBuffer, {
		off = off,
		data = data,
	})
	table.sort(self.pendingReadBuffer, function(a, b)
		return a.off < b.off
	end)

	while self.pendingReadBuffer[1].off == self.currentOffset do
		local d = self.pendingReadBuffer[1].data
		self.readBuffer = self.readBuffer .. d
		self.currentOffset = self.currentOffset + #d
		table.remove(self.pendingReadBuffer, 1)
		if not self.pendingReadBuffer[1] then break end
	end

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

---@param c string
---@param n? integer
---@return boolean
function stream:bufferHas(c, n)
	n = n or 1
	local ptr = 1
	for _=1,n do
		local i = string.find(self.readBuffer, c, ptr, true)
		if i == nil then return false end
		ptr = i + 1
	end
	return true
end

---@param n integer
---@return string?
function stream:read(n)
	if self:isClosed() then return end
	self:blockForWrites()
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
	self:blockForWrites()
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

---@return string?
function stream:readLine()
	return self:readUntil("\n")
end

---@return string?
function stream:readCString()
	return self:readUntil("\0")
end

function stream:_unsafe_handleAck()
	self.pendingWritePacketsLeft = self.pendingWritePacketsLeft - 1
	if self.pendingWritePacketsLeft == 0 then
		-- successful transmission
		if not self.packetsWereLost then
			self.congestionWindow = math.min(self.congestionWindow * 2, osp.maximumCongestionWindow)
		end
		if #self.pendingWriteBuffer > 0 then
			local buf = table.remove(self.pendingWriteBuffer, 1)
			self:writeAsync(buf.data, buf.blockSize)
		end
	end
end

function stream:_unsafe_handleLoss()
	self.packetsWereLost = true
	self.congestionWindow = math.max(self.congestionWindow - 1, osp.minimumCongestionWindow)
end

---@param data string
---@param blockSize? integer
---@param maxConcurrentPackets? integer
function stream:writeAsync(data, blockSize, maxConcurrentPackets)
	if self:isDisconnected() then return end

	blockSize = blockSize or atomnet.recommendedBufferSize()
	maxConcurrentPackets = maxConcurrentPackets or self.congestionWindow
	assert(blockSize <= 65535, "invalid blocksize") -- u16 limit

	if self:writesPending() then
		table.insert(self.pendingWriteBuffer, {
			data = data,
			blockSize = blockSize,
		})
		return
	end

	if #data > blockSize * maxConcurrentPackets then
		-- we need segmentation
		local segmentSize = blockSize * maxConcurrentPackets
		table.insert(self.pendingWriteBuffer, {
			data = data:sub(segmentSize+1),
			blockSize = blockSize,
		})
		data = data:sub(1, segmentSize)
	end

	local packetCount = math.ceil(#data / blockSize)
	self.pendingWritePacketsLeft = packetCount
	for i=1, #data, blockSize do
		local chunk = data:sub(i, i + blockSize - 1)
		local encoded = string.pack(">I4>I2", self.writingOffset + i - 1, #chunk) .. chunk
		rcps.sendAsync(self.session, encoded)
	end
	self.writingOffset = self.writingOffset + #data
end

---@param data string
---@param blockSize? integer
function stream:write(data, blockSize)
	if self:isDisconnected() then return end

	self:writeAsync(data, blockSize)
	self:blockForWrites()
end

function stream:blockForWrites()
	while true do
		if not self:writesPending() then
			break
		end
		local e = event.pull()
		if e == "interrupted" then
			error("interrupted", 2)
		end
	end
end

function stream:writesPending()
	return self.pendingWritePacketsLeft > 0 and (not self:isDisconnected())
end

function stream:disconnect()
	self:blockForWrites()
	rcps.disconnect(self.session, rcps.exit.closed, "")
	-- cleans up memory faster
	self.pendingReadBuffer = {}
end

function stream:close()
	self:disconnect()
	self.readBuffer = "" -- stops reading
end


---@type rcps.vtable
local _CLIENT_VTABLE = {
	connected = function (sesh, encryption)
		sesh.data = stream.new(sesh)
	end,
	disconnected = function (sesh, exitCode, msg)
		---@type osp.stream
		local s = sesh.data
		if not s then return end
		s:disconnect()
	end,
	timeout = function (sesh, packetID)
		---@type osp.stream
		local s = sesh.data
		if not s then return end
		s:disconnect()
	end,
	responded = function (sesh, packetID, accepted, response)
		---@type osp.stream
		local s = sesh.data
		if not s then return end
		if not accepted then s:disconnect() end
		s:_unsafe_handleAck()
	end,
	sent = function (sesh, data)
		---@type osp.stream
		local s = sesh.data
		if not s then return false, "" end
		s:_unsafe_handlePacket(data)
		return true, ""
	end,
	lost = function(sesh, id)
		---@type osp.stream
		local s = sesh.data
		if not s then return end
		s:_unsafe_handleLoss()
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
			s:_unsafe_handleAck()
		end,
		sent = function (sesh, data)
			---@type osp.stream
			local s = sesh.data
			s:_unsafe_handlePacket(data)
			return true, ""
		end,
		lost = function(sesh, id)
			---@type osp.stream
			local s = sesh.data
			s:_unsafe_handleAck()
		end,
	}

	return rcps.open(port, _SRVR_VTABLE, keys)
end

---@param port integer
function osp.close(port)
	rcps.close(port)
end

return osp
