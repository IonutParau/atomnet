-- Segmented Node Protocol
-- It is as reliable as AtomNET is, which means
-- it is up to the network configuration and state.
-- It is useful for unreliable but fast communications.
-- Upon receiving data on an open port, it will push
-- a snp_data signal of signature
-- snp_data(srcAddress: integer, srcPort: integer, port: integer, data: string)
--[[

// big endian

struct snp_packet {
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint8_t data[length];
};

]]

local atomnet = require("atomnet")
local event = require("event")

local snp = {}

snp.protocol = atomnet.protocols.SegmentedNodeProtocol

---@type table<integer, boolean>
local _PORT_MAP = {}

local function snp_atom_msg(_, src, protocol, packet)
	if protocol ~= snp.protocol then return end

	local sourcePort = string.unpack(">I2", packet)
	local destPort = string.unpack(">I2", packet, 3)
	local len = string.unpack(">I2", packet, 5)
	local data = string.sub(packet, 7, 6 + len)

	if not _PORT_MAP[destPort] then return end -- not open, random spam

	atomnet.log("SNP packet from %s:%d on port %d", atomnet.formatAddress(src), sourcePort, destPort)
	event.push("snp_data", src, sourcePort, destPort, data)
end

function snp.init()
	event.listen("atom_msg", snp_atom_msg)
end

function snp.deinit()
	event.ignore("atom_msg", snp_atom_msg)
end

snp.MIN_PORT_ALLOC = 8192
snp.MAX_PORT_ALLOC = 65535

function snp.setPortAllocationRange(min, max)
	assert(max >= min, "bad range")
	snp.MIN_PORT_ALLOC = math.max(min, 0)
	snp.MAX_PORT_ALLOC = math.min(max, 65535)
end

---@param port integer
function snp.validPort(port)
	return port >= 0 and port <= 65535
end

---@param port integer
---@return boolean
function snp.isPortOpen(port)
	-- or false since if port is closed, it's nil
	return _PORT_MAP[port] or false
end

---@return integer
function snp.findAvailablePort()
	local p = snp.MIN_PORT_ALLOC
	while _PORT_MAP[p] do
		p = p + 1
		if p > snp.MAX_PORT_ALLOC then
			error("too many ports")
		end
	end
	return p
end

---@param port? integer
function snp.open(port)
	port = port or snp.findAvailablePort()
	_PORT_MAP[port] = true
	return port
end

---@param port? integer
function snp.close(port)
	if not port then
		_PORT_MAP={}
		return
	end
	_PORT_MAP[port] = nil
end

function snp.sendTo(destination, destinationPort, sourcePort, data)
	local packet = string.pack(">I2>I2>I2", sourcePort, destinationPort, #data) .. data
	atomnet.sendTo(destination, snp.protocol, packet)
end

return snp
