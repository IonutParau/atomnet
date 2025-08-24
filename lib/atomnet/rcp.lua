-- Remote Communication Protocol

--[[
// big endian

struct rcp_packet {
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint8_t role;
	uint32_t id;
	union {
		rcp_data data;
		rcp_ack ack;
	};
};

enum rcp_role {
	DATA = 0,
	ACK = 1,
};

struct rcp_data {
	uint16_t length;
	uint8_t data[length];
};

struct rcp_ack {
	uint8_t ackFlags;
	// this can save backtrip
	uint16_t length;
	uint8_t data[length];
};

enum rcp_ackFlags {
	REJECTED = 1, // acknowledged, but faulty. Useful for some protocols.
};

]]

--[[
-- Signals

rcp_data(srcAddress: integer, srcPort: integer, port: integer, data: string, packetID: string)
rcp_ack(srcAddress: integer, srcPort: integer, port: integer, data: string, packetID: string)
rcp_rejected(srcAddress: integer, srcPort: integer, port: integer, data: string, packetID: string)
rcp_timeout(srcAddress: integer, srcPort: integer, port: integer, packetID: string)
rcp_lost(srcAddress: integer, srcPort: integer, port: integer, packetID: string)
]]

local atomnet = require("atomnet")
local event = require("event")
local computer = require("computer")

local rcp = {}
rcp.protocol = atomnet.protocols.RemoteCommunicationProtocol

--- Called on every packet.
--- It returns whether the packet has been *rejected*, meaning no signal is queued,
--- and if it is, what data (if any) to add there.
--- If the acknowledgement fails to send, the middleware isn't called again.
--- Instead, the acknowledgement is cached for some time.
---@alias rcp.middleware fun(source: integer, sourcePort: integer, data: string): boolean, string?

---@type rcp.middleware
local function rcp_defaultMiddleware(source, sourcePort, data)
	-- never reject
	return false
end

---@type table<integer, rcp.middleware>
local _PORT_MAP = {}

---@param source integer
---@param sourcePort integer
---@param port integer
---@param packetID string
local function rcp_computePacketUUID(source, sourcePort, port, packetID)
	return atomnet.addressToBytes(source) .. string.pack(">I2>I2", sourcePort, port) .. packetID
end

---@class rcp.faultyPacket
---@field uuid string
---@field src atomnet.address
---@field srcPort integer
---@field port integer
---@field packetID string
---@field data string
---@field timeout number
---@field timeoutDeadline number
---@field timesLeft integer

---@type rcp.faultyPacket[]
local _NOT_YET_RECEIVED = {}

---@class rcp.dedupe
---@field uuid string
---@field fullySerializedAcknowledgementPacket string

local _MAX_DEDUPES = 128

---@type rcp.dedupe[]
local _DEDUPES = {}

local function rcp_encode_ack(srcPort, destPort, rejected, id, data)
	local encoded = string.pack(">I2>I2>I1", srcPort, destPort, 1) .. id
	encoded = encoded .. string.char(rejected and 1 or 0)
	encoded = encoded .. string.pack(">I2", #data) .. data
	return encoded
end

---@param packet rcp.faultyPacket
local function rcp_emit_packet(packet)
	local encoded = string.pack(">I2>I2>I1", packet.port, packet.srcPort, 0) .. packet.packetID .. string.pack(">I2", #packet.data) .. packet.data
	atomnet.sendTo(packet.src, rcp.protocol, encoded)
end

---@param src integer
---@param protocol integer
---@param packet string
local function rcp_atom_msg(_, src, protocol, packet)
	if protocol ~= rcp.protocol then return end

	local srcPort, destPort, role, id = string.unpack(">I2>I2>I1c4", packet)

	-- TODO: check if the port is fucking open

	if role == 0 then
		local uuid = rcp_computePacketUUID(src, srcPort, destPort, id)
		for _, dedupe in ipairs(_DEDUPES) do
			if dedupe.uuid == uuid then
				atomnet.sendTo(src, rcp.protocol, dedupe.fullySerializedAcknowledgementPacket)
				return
			end
		end
		local len = string.unpack(">I2", packet, 10)
		local data = string.sub(packet, 12, 11 + len)
		local middleware = _PORT_MAP[destPort]
		if not middleware then
			return
		end
		local rejected, reason = middleware(src, srcPort, data)
		local encoded = rcp_encode_ack(destPort, srcPort, rejected, id, reason or "")
		---@type rcp.dedupe
		local dedupe = {
			uuid = uuid,
			fullySerializedAcknowledgementPacket = encoded,
		}
		table.insert(_DEDUPES, dedupe)
		while #_DEDUPES > _MAX_DEDUPES do
			table.remove(_DEDUPES, 1)
		end

		atomnet.sendTo(src, rcp.protocol, encoded)
		event.push("rcp_data", src, srcPort, destPort, data, id)
		return
	end
	if role == 1 then
		local uuid = rcp_computePacketUUID(src, srcPort, destPort, id)
		for i=#_NOT_YET_RECEIVED, 1, -1 do
			local p = _NOT_YET_RECEIVED[i]
			if p.uuid == uuid then
				-- received! We're good!
				table.remove(_NOT_YET_RECEIVED, i)
				local flags = string.byte(packet, 10)
				local len = string.unpack(">I2", packet, 11)
				local data = string.sub(packet, 13, 12 + len)
				event.push(flags == 1 and "rcp_rejected" or "rcp_ack", src, srcPort, destPort, data, id)
				return
			end
		end
		-- prob a dupe
		return
	end
end

---@param destAddr atomnet.address
---@param destPort integer
---@param port integer
---@param data string
---@param timeout? integer
---@param times? integer
---@return string
function rcp.writeAsync(destAddr, destPort, port, data, timeout, times)
	timeout = timeout or 3
	times = times or 3
	local packetID = atomnet.randomPacketID()

	local uuid = rcp_computePacketUUID(destAddr, destPort, port, packetID)

	---@type rcp.faultyPacket
	local p = {
		uuid = uuid,
		data = data,
		packetID = packetID,
		port = port,
		src = destAddr,
		srcPort = destPort,
		timeoutDeadline = computer.uptime() + timeout,
		timeout = timeout,
		timesLeft = times,
	}

	table.insert(_NOT_YET_RECEIVED, p)
	rcp_emit_packet(p)
	return packetID
end

---@param destAddr atomnet.address
---@param destPort integer
---@param port integer
---@param data string
---@param timeout? integer
---@param times? integer
---@return boolean, string?
--- Returns whether it was accepted and the reason message (if non-empty)
--- In the case of timeouts or interrupted, this will error.
function rcp.write(destAddr, destPort, port, data, timeout, times)
	local id = rcp.writeAsync(destAddr, destPort, port, data, timeout, times)
	while true do
		local e = {event.pull()}
		if e[1] == "interrupted" then
			error("interrupted", 2)
		end
		if e[1] == "rcp_timeout" and e[2] == destAddr and e[3] == destPort and e[4] == port and e[5] == id then
			error("timeout", 2)
		end
		if e[1] == "rcp_ack" and e[2] == destAddr and e[3] == destPort and e[4] == port and e[6] == id then
			local reason = e[5]
			if reason == "" then reason = nil end
			return true, reason
		end
		if e[1] == "rcp_rejected" and e[2] == destAddr and e[3] == destPort and e[4] == port and e[6] == id then
			local reason = e[5]
			if reason == "" then reason = nil end
			return false, reason
		end
	end
end

local function rcp_timer()
	local now = computer.uptime()

	for i=#_NOT_YET_RECEIVED, 1, -1 do
		local p = _NOT_YET_RECEIVED[i]

		if p.timeoutDeadline <= now then
			-- yet another timeout
			p.timesLeft = p.timesLeft - 1
			if p.timesLeft > 0 then
				p.timeoutDeadline = now + p.timeout
				event.push("rcp_lost", p.src, p.srcPort, p.port, p.uuid)
				rcp_emit_packet(p)
			else
				-- just... bye bye
				table.remove(_NOT_YET_RECEIVED, i)
				event.push("rcp_timeout", p.src, p.srcPort, p.port, p.packetID)
			end
		end
	end
end

local _RCP_TIMER_ID

function rcp.init()
	event.listen("atom_msg", rcp_atom_msg)
	_RCP_TIMER_ID = event.timer(0, rcp_timer, math.huge)
end

function rcp.deinit()
	event.ignore("atom_msg", rcp_atom_msg)
	event.cancel(_RCP_TIMER_ID)
end

rcp.MIN_PORT_ALLOC = 8192
rcp.MAX_PORT_ALLOC = 65535

function rcp.setPortAllocationRange(min, max)
	assert(max >= min, "bad range")
	rcp.MIN_PORT_ALLOC = math.max(min, 0)
	rcp.MAX_PORT_ALLOC = math.min(max, 65535)
end

---@param port integer
function rcp.validPort(port)
	return port >= 0 and port <= 65535
end

---@param port integer
---@return boolean
function rcp.isPortOpen(port)
	return _PORT_MAP[port] ~= nil
end

---@return integer
function rcp.findAvailablePort()
	local r = math.random(rcp.MIN_PORT_ALLOC, rcp.MAX_PORT_ALLOC)
	-- gambling
	if not _PORT_MAP[r] then return r end

	local p = rcp.MIN_PORT_ALLOC
	while _PORT_MAP[p] do
		p = p + 1
		if p > rcp.MAX_PORT_ALLOC then
			error("too many ports")
		end
	end
	return p
end

---@param port? integer
---@param middleware? rcp.middleware
function rcp.open(port, middleware)
	port = port or rcp.findAvailablePort()
	_PORT_MAP[port] = middleware or rcp_defaultMiddleware
	return port
end

---@param port? integer
function rcp.close(port)
	if not port then
		_PORT_MAP={}
		return
	end
	_PORT_MAP[port] = nil
end

return rcp
