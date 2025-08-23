local event = require("event")
local component = require("component")
local computer = require("computer")
local bit32 = require("bit32")

-- Generic format
--[[

// in big endian

typedef uint32_t atom_address;

struct atom_packet {
	char header[] = "ATOM\0";
	uint8_t version; // current version is 0
	uint16_t action; // see atomnet.actions for numbers
	union {
		atom_transmit;
		atom_discover;
		atom_identity;
	};
};

struct atom_transmit {
	atom_address source;
	atom_address destination;
	atom_address redirectedFor;
	uint32_t randID; // random ID for deduplication
	uint8_t protocol; // see atomnet.protocols for numbers
	uint8_t hopsAllowed; // if this is 0 and a hop is needed, send back to source an NMP too many hops message
	uint16_t length;
	uint8_t headerChecksum; // checksum of everything until (not including) this field
	uint8_t dataChecksum; // checksum of everything after this field
	uint8_t data[length];
};

struct atom_discover {
	atom_address discoverer;
	uint16_t msgLength;
	uint8_t msgData[keyLength];
};

struct atom_identity {
	atom_address discovered;
	uint8_t atomVersionSupported;
	uint8_t nameLength;
	uint8_t name[nameLength];
};

]]

local atomnet = {}

--- A utility function for dumping hex in a standard way
---@param s string
---@return string
function atomnet.hexdump(s)
	local h = ""
	for i=1,#s do
		h = h .. string.format("%02x", s:byte(i, i))
	end
	return h
end

---@param s string
---@return string
function atomnet.hexload(s)
	assert(#s % 2 == 0, "bad length")
	local alpha = "0123456789abcdef"
	local map = {}
	for i=1,#alpha do
		map[alpha:sub(i, i)] = i - 1
	end

	local out = ""
	for i=1,#s,2 do
		local upper = s:sub(i, i):lower()
		local lower = s:sub(i+1, i+1):lower()

		local byte = map[upper] * 16 + map[lower]
		out = out .. string.char(byte)
	end
	return out
end

atomnet.PORT = 0x0C19

atomnet.HEADER = "ATOM\0"
atomnet.VERSION = 0

atomnet.reliability = 1

---@enum atomnet.medium
atomnet.mediums = {
	modem = "modem",
	tunnel = "tunnel",
	-- everything sent to void is discared as junk
	void = "void",
}

---@enum atomnet.action
atomnet.actions = {
	TRANSMIT = 0x00,
	DISCOVER = 0x01,
	IDENTITY = 0x02,
}

---@enum atomnet.protocol
atomnet.protocols = {
	-- message is sent directly as data, used by atomnet chat
	-- this is mostly used for super basic chatting
	DirectMessage = 0x00,
	-- a basic protocol for validating networks or getting error messages
	-- it allows pinging, error messages and requesting metadata
	--[[
		struct networkcheck_packet {
			uint8_t type;
			uint8_t code;
			union {
				networkcheck_ping ping;
				networkcheck_routenode routenode; // assembled by traceroute during transmission of traceroute, replied to by routenode
			};
		};

		enum networkcheck_type {
			PING = 0,
			PONG = 1, // reply to a PING
			TRACEROUTE = 2,
			ROUTENODE = 3, // reply to traceroute transmission
		};

		struct networkcheck_ping {
			uint8_t len;
			uint8_t data[len];
		};
		
		struct networkcheck_routenode {
			uint8_t length;
			uint32_t route[length];
		};
	]]
	NetworkCheck = 0x01,
	-- handles DNS resolution
	-- Reliability is more in timeouts and retries
	--[[
		struct remotehost_packet {
			uint8_t type; // 0 for request, 1 for response
			union {
				remotehost_request request;
				remotehost_response response;
			}
		};

		struct remotehost_request {
			uint8_t len;
			uint8_t hostname[len];
		};
		
		struct remotehost_response {
			uint32_t atomnetAddress; // 0.0.0.0 for not found
			uint8_t len;
			uint8_t hostname[len];
		};
	]]
	-- Deprecated, unsupported, no one likes it
	--RemoteHostsSource = 0x02,
	-- see /lib/atomnet/snp.lua
	SegmentedNodeProtocol = 0x03,
	-- see /lib/atomnet/rcp.lua
	RemoteCommunicationProtocol = 0x04,
}


---@alias atomnet.address integer

atomnet.address = 0x00
atomnet.hostname = computer.address():sub(1, 8)

atomnet.broadcastOnUnknown = true
---@type {min: integer, max: integer, towards: string, medium: atomnet.medium}[]
atomnet.addressRangeOverrides = {}

-- Nil to disable
-- If not nil, this will be used to remember addresses received
-- This combined with broadcastOnUnknown works like minitel.
---@alias atomnet.backtracked {device: string, medium: atomnet.medium, address: integer, expires: number, hop: integer}
---@type atomnet.backtracked[]?
atomnet.backtrackingMemory = {}

---@type table<string, {address: integer, distance?: number, medium: atomnet.medium, uptimeAtIdentification: number, name: string}>
atomnet.identified = {}

---@param data string
---@return integer
function atomnet.checksum(data)
	local sum16 = 0

	for i=1,#data do
		sum16 = sum16 + data:byte(i,i)
	end

	-- simulate 16-bit sum
	sum16 = sum16 % 65536

	local lower = sum16 % 256
	local upper = math.floor(sum16 / 256)

	return bit32.bxor(lower, upper)
end

---@param address integer
function atomnet.formatAddress(address)
	local bytes = atomnet.addressToBytes(address)

	local a, b, c, d = string.byte(bytes, 1, 4)

	return string.format("%d.%d.%d.%d", a, b, c, d)
end

---@param address integer
---@return atomnet.backtracked[], integer
function atomnet.getBacktrackingFor(address)
	---@type atomnet.backtracked[]
	local backtracked = {}
	local totalHops = 0

	if atomnet.backtrackingMemory then
		for i=1,#atomnet.backtrackingMemory do
			local node = atomnet.backtrackingMemory[i]

			if node.address == address then
				table.insert(backtracked, node)
				totalHops = totalHops + node.hop
			end
		end
	end

	return backtracked, totalHops
end

---@param node atomnet.backtracked
function atomnet.rememberBacktracking(node)
	if not atomnet.backtrackingMemory then return end

	for _, remembered in ipairs(atomnet.backtrackingMemory) do
		if remembered.address == node.address
			and remembered.device == node.device
			and remembered.medium == node.medium then
			remembered.hop = math.max(remembered.hop, node.hop)
			return
		end
	end

	table.insert(atomnet.backtrackingMemory, node)
end

---@type table<string, integer>
atomnet.hosts = {}

atomnet.handleRouting = true
atomnet.includeInTraceroute = true

function atomnet.randomAddress()
	return atomnet.addressFromBytes(atomnet.randomPacketID()) -- packet IDs are the same size as addresses
end

---@param address string
function atomnet.isValidAddress(address)
	local ok = string.find(address, "^(%d+).(%d+).(%d+).(%d+)$")
	return ok ~= nil
end

---@param address string
---@return integer
function atomnet.parseAddress(address)
	local ok, _, a, b, c, d = string.find(address, "^(%d+).(%d+).(%d+).(%d+)$")

	assert(ok, "invalid address")

	a = assert(tonumber(a))
	b = assert(tonumber(b))
	c = assert(tonumber(c))
	d = assert(tonumber(d))

	local encoded = string.char(a, b, c, d)
	return atomnet.addressFromBytes(encoded)
end

---@param address string 
---@return integer
function atomnet.addressFromBytes(address)
	return (string.unpack(">I4", address))
end

---@param address integer
---@return string
function atomnet.addressToBytes(address)
	return (string.pack(">I4", address))
end

atomnet.MAX_LOGS = 1024
atomnet.logs = {}

function atomnet.log(fmt, ...)
	local s = string.format(fmt, ...)
	table.insert(atomnet.logs, s)
	while #atomnet.logs > atomnet.MAX_LOGS do
		table.remove(atomnet.logs, 1)
	end
end

atomnet.loopbackAddress = atomnet.parseAddress"127.0.0.1"
atomnet.hosts.localhost = atomnet.loopbackAddress

---@param packet string
---@param from string
---@param medium atomnet.medium
---@param distance? number
function atomnet.processPacket(packet, from, medium, distance)
	if string.sub(packet, 1, 5) ~= atomnet.HEADER then return end

	local ver = string.byte(packet, 6)
	if ver > atomnet.VERSION then return end

	local action = string.unpack(">I2", packet, 7)
	local actionData = string.sub(packet, 9)

	atomnet.processAction(action, actionData, from, medium, distance)
end

---@param action integer
---@param actionData string
---@param from string
---@param medium atomnet.medium
---@param distance? number
function atomnet.processAction(action, actionData, from, medium, distance)
	if action == atomnet.actions.DISCOVER then
		if atomnet.address == 0 then return end -- node is not set up
		local addr = atomnet.formatAddress(atomnet.addressFromBytes(string.sub(actionData, 1, 4)))
		local msglen = string.unpack(">I2", actionData, 2)
		local msg = string.sub(actionData, 7, 7 + msglen - 1)
		-- events!!!!
		if not atomnet.identified[from] then atomnet.log("%s discovered us: %s", addr, msg) end
		-- send back!
		local idData = atomnet.addressToBytes(atomnet.address) .. string.char(atomnet.VERSION) .. string.char(#atomnet.hostname) .. atomnet.hostname
		atomnet.sendRaw(from, medium, atomnet.actions.IDENTITY, idData)
	end
	if action == atomnet.actions.IDENTITY then
		local discovered = atomnet.addressFromBytes(string.sub(actionData, 1, 4))
		local atomVer = string.byte(actionData, 5, 5)
		local nameLen = string.byte(actionData, 6, 6)
		local name = string.sub(actionData, 7, 7 + nameLen - 1)
		if not atomnet.identified[from] then atomnet.log("discovered %s (%q, v%d)", atomnet.formatAddress(discovered), name, atomVer) end
		atomnet.identified[from] = {
			address = discovered,
			medium = medium,
			name = name,
			distance = distance,
			uptimeAtIdentification = computer.uptime(),
		}
	end
	if action == atomnet.actions.TRANSMIT then
		local src = atomnet.addressFromBytes(string.sub(actionData, 1, 4))
		local dest = atomnet.addressFromBytes(string.sub(actionData, 5, 8))
		local redirectedFor = atomnet.addressFromBytes(string.sub(actionData, 9, 12))
		local randID = string.sub(actionData, 13, 16)
		local protocol = string.byte(actionData, 17)
		local hops = string.byte(actionData, 18)
		local len = string.unpack(">I2", actionData, 19)
		local headerChecksum = string.byte(actionData, 21)
		local dataChecksum = string.byte(actionData, 22)
		local data = string.sub(actionData, 23, 22 + len)

		local header = string.sub(actionData, 1, 20)

		if (atomnet.checksum(header) ~= headerChecksum) or (atomnet.checksum(data) ~= dataChecksum) then
			atomnet.log("corrupted transmission allegedly from %s -> %s for %s (%d bytes)", atomnet.formatAddress(src), atomnet.formatAddress(dest), atomnet.formatAddress(redirectedFor), len)
			return
		end

		atomnet.log("transmission from %s -> %s for %s (%d bytes)", atomnet.formatAddress(src), atomnet.formatAddress(dest), atomnet.formatAddress(redirectedFor), len)

		atomnet.receivedTransmission(src, dest, redirectedFor, protocol, hops, data, from, medium, randID)
	end
end

---@type {hash: string, expires: number}[]
atomnet.lastPackets = {}

local _MAX_LAST_PACKETS = 64

---@param src integer
---@param dest integer
---@param protocol integer
---@param id string
function atomnet.hashTransmission(src, dest, protocol, id)
	local hash = atomnet.addressToBytes(src) .. atomnet.addressToBytes(dest) .. string.char(protocol) .. id
	return hash
end

---@param src atomnet.address
---@param data string
function atomnet.handleNetworkCheck(src, data)
	local type = string.byte(data, 1, 1)
	local code = string.byte(data, 2, 2)

	-- Ping!!!!
	if type == 0 then
		local len = string.byte(data, 3, 3)
		local pingData = string.sub(data, 4, 3 + len)

		local pong = string.char(1, 0, len) .. pingData

		atomnet.sendTo(src, atomnet.protocols.NetworkCheck, pong)
	end

	if type == 1 then
		local len = string.byte(data, 3, 3)
		local pingData = string.sub(data, 4, 3 + len)

		computer.pushSignal("atom_pong", src, pingData)
	end

	if type == 2 then
		local len = string.byte(data, 3, 3)
		local addresses = string.sub(data, 4, 3 + len * 4)

		atomnet.sendTo(src, atomnet.protocols.NetworkCheck, string.char(3, 0, len) .. addresses)
	end

	if type == 3 then
		local len = string.byte(data, 3, 3)
		local addresses = string.sub(data, 4, 3 + len * 4)

		local ips = {}
		for i=1,len do
			table.insert(ips, atomnet.addressFromBytes(string.sub(addresses, (i - 1) * 4 + 1, i * 4)))
		end

		computer.pushSignal("atom_traceroute", src, ips)
	end
end

---@param address integer
---@param data string
function atomnet.ping(address, data)
	assert(#data < 256, "too much data")

	local ping = string.char(0, 0, #data) .. data
	atomnet.sendTo(address, atomnet.protocols.NetworkCheck, ping)
end

-- 0 means all nodes are available
-- 1 would mean the node with the highest hops left is used
-- It is recommended to set it to a small fraction of the routes available
atomnet.maxLoadBalancingNodes = 0

---@param src integer
---@param dest integer
---@param redirectedFor integer
---@param protocol integer
---@param data string
---@param device string
---@param medium atomnet.medium
---@param id string
function atomnet.receivedTransmission(src, dest, redirectedFor, protocol, hops, data, device, medium, id)
	if dest == atomnet.loopbackAddress then return end -- void address

	if math.random() >= atomnet.reliability then
		atomnet.log("transmission discarded")
		return
	end

	if redirectedFor == atomnet.address then
		return -- something sent it back to us by mistake
	end

	local redirectedFrom
	if atomnet.identified[device] then
		redirectedFrom = atomnet.identified[device].address
	end
	if device == computer.address() then
		redirectedFrom = atomnet.address
	end

	if redirectedFor ~= src and redirectedFrom ~= src then
		for _, node in pairs(atomnet.identified) do
			if node.address == redirectedFor then
				return -- unnecessary hop, either bad network design or pointless redundancy
			end
		end
	end

	if not redirectedFrom then return end

	if medium ~= "void" then
		if atomnet.backtrackingMemory then
			atomnet.cleanUpBacktracking()
			-- actually remember this device!!!!
			-- we do it in this way so latency doesn't fuck us over
			atomnet.rememberBacktracking {
				device = device,
				medium = medium,
				address = src,
				hop = hops,
				expires = computer.uptime() + 10,
			}
		end
	end

	local now = computer.uptime()
	while true do
		if not atomnet.lastPackets[1] then break end
		if atomnet.lastPackets[1].expires > now then break end
		table.remove(atomnet.lastPackets, 1)
	end
	local hash = atomnet.hashTransmission(src, dest, protocol, id)
	for i=1,#atomnet.lastPackets do
		if atomnet.lastPackets[i].hash == hash then
			atomnet.log("Duplicate packet from %s to %s", atomnet.formatAddress(src), atomnet.formatAddress(dest))
			return
		end
	end
	table.insert(atomnet.lastPackets, {
		expires = now + 30,
		hash = hash,
	})
	if #atomnet.lastPackets > _MAX_LAST_PACKETS then
		table.remove(atomnet.lastPackets, 1)
	end

	if protocol == atomnet.protocols.NetworkCheck then
		if data:byte(1, 1) == 2 and atomnet.includeInTraceroute then
			-- traceroute
			local len = data:byte(3, 3) or 0
			local addresses = data:sub(4, 3 + len * 4)
			addresses = addresses .. atomnet.addressToBytes(atomnet.address)
			data = string.char(2, 0, len + 1) .. addresses
			atomnet.log("Route being traced by %s", atomnet.formatAddress(src))
		end
	end

	if dest == atomnet.address then
		atomnet.log("Received %d bytes (protocol %d) from %s (%d hops left)", #data, protocol, atomnet.formatAddress(src), hops)
		computer.pushSignal("atom_msg", src, protocol, data)
		if protocol == atomnet.protocols.NetworkCheck then
			atomnet.handleNetworkCheck(src, data)
		end
		return
	end

	-- not a router, just a client
	if src ~= atomnet.address and (not atomnet.handleRouting) then
		return
	end

	if hops == 0 then
		-- welp, sucks to suck
		atomnet.log("TRANSMISSION FROM %s EXPIRED", atomnet.formatAddress(src))
		return
	end
	hops = hops - 1
	if atomnet.backtrackingMemory then
		local nodes = atomnet.getBacktrackingFor(dest)
		if #nodes > 0 then
			local loadBalancingNodes = #nodes
			if atomnet.maxLoadBalancingNodes > 0 then
				loadBalancingNodes = math.min(atomnet.maxLoadBalancingNodes, #nodes)
				table.sort(nodes, function(a, b)
					return a.hop > b.hop
				end)
			end
			local node = nodes[math.random(1, loadBalancingNodes)]
			atomnet.sendTransmission(node.device, node.medium, src, dest, redirectedFrom, protocol, data, hops, id)
			return
		end
	end
	if atomnet.broadcastOnUnknown then
		-- BROADCAST!!!!
		atomnet.sendTransmission("broadcast", atomnet.mediums.modem, src, dest, redirectedFrom, protocol, data, hops, id)
		atomnet.sendTransmission("broadcast", atomnet.mediums.tunnel, src, dest, redirectedFrom, protocol, data, hops, id)
		return
	end
end

---@param address integer
function atomnet.isLoopback(address)
	local min = atomnet.parseAddress"127.0.0.1"
	local max = atomnet.parseAddress"127.0.0.255"

	return address >= min and address <= max
end

---@param address integer
---@param protocol integer
---@param data string
---@param hops? integer
function atomnet.sendTo(address, protocol, data, hops)
	local randID = atomnet.randomPacketID()
	hops = hops or 255
	if atomnet.isLoopback(address) then
		atomnet.receivedTransmission(atomnet.loopbackAddress, atomnet.address, atomnet.loopbackAddress, protocol, hops, data, computer.address(), "void", randID)
		return
	end
	atomnet.receivedTransmission(atomnet.address, address, atomnet.loopbackAddress, protocol, hops, data, computer.address(), "void", randID)
end

function atomnet.modemHandler(_, receiver, sender, port, distance, firstVal)
	if component.type(receiver) == "tunnel" then
		atomnet.processPacket(firstVal, receiver, atomnet.mediums.tunnel, distance)
		return
	end

	if port ~= atomnet.PORT then return end

	if type(firstVal) ~= "string" then return end

	if not atomnet.primaryModem then return end

	if atomnet.primaryModem.address ~= receiver then return end

	atomnet.processPacket(firstVal, sender, atomnet.mediums.modem, distance)
end

atomnet.primaryModem = nil

function atomnet.switchModem(address)
	if atomnet.primaryModem then
		atomnet.primaryModem.close(atomnet.PORT)
	end

	if not address then return end
	assert(component.type(address) == "modem", "not a modem")

	atomnet.primaryModem = component.proxy(address)
	atomnet.primaryModem.open(atomnet.PORT)
end

_DISCOVERY_INTERVAL = 5

local _DISCOVERY_TIMER

function atomnet.cleanUpBacktracking()
	local now = computer.uptime()
	-- backtracking GC
	for i=#atomnet.backtrackingMemory, 1, -1 do
		if atomnet.backtrackingMemory[i].expires <= now then
			table.remove(atomnet.backtrackingMemory, i)
		end
	end
end

function atomnet.cleanUpDedupes()
	while true do
		local now = computer.uptime()
		if not atomnet.lastPackets[1] then break end
		if atomnet.lastPackets[1].expires > now then break end
		table.remove(atomnet.lastPackets, 1)
	end
end

local function discoveryClock()
	atomnet.forgetAllAfter(_DISCOVERY_INTERVAL*2)
	atomnet.cleanUpBacktracking()
	atomnet.cleanUpDedupes()

	atomnet.discover(atomnet.hostname)
end

function atomnet.init()
	if component.isAvailable("modem") then
		atomnet.switchModem(component.modem.address)
	end
	event.listen("modem_message", atomnet.modemHandler)
	_DISCOVERY_TIMER = event.timer(_DISCOVERY_INTERVAL, discoveryClock, math.huge)
	atomnet.discover("setup")
end

function atomnet.deinit()
	atomnet.switchModem(nil)
	event.ignore("modem_message", atomnet.modemHandler)
	event.cancel(_DISCOVERY_TIMER)
end

function atomnet.encodeRaw(action, data)
	return atomnet.HEADER .. string.char(atomnet.VERSION) .. string.pack(">I2", action) .. data
end

function atomnet.sendRaw(address, medium, action, data)
	local encoded = atomnet.encodeRaw(action, data)
	if medium == atomnet.mediums.modem and atomnet.primaryModem then
		if address == "broadcast" then
			return atomnet.primaryModem.broadcast(atomnet.PORT, encoded)
		end
		return atomnet.primaryModem.send(address, atomnet.PORT, encoded)
	end
	if medium == atomnet.mediums.tunnel then
		if address == "broadcast" then
			for addr in component.list("tunnel", true) do
				component.invoke(addr, "send", encoded)
			end
			return
		end
		return component.invoke(address, "send", encoded)
	end
end

function atomnet.randomPacketID()
	local s = ""
	for _=1,4 do
		s = s .. string.char(math.random(0, 255))
	end
	return s
end

---@param address string
---@param medium atomnet.medium
---@param src integer
---@param dest integer
---@param redirectedFor integer
---@param protocol integer
---@param data string
---@param maxHops integer
---@param id string
function atomnet.sendTransmission(address, medium, src, dest, redirectedFor, protocol, data, maxHops, id)
	assert(#id == 4, "invalid ID")
	local encoded = atomnet.addressToBytes(src)
	.. atomnet.addressToBytes(dest)
	.. atomnet.addressToBytes(redirectedFor)
	.. id
	.. string.char(protocol)
	.. string.char(maxHops)
	.. string.pack(">I2", #data)

	local headerChecksum = atomnet.checksum(encoded)
	local dataChecksum = atomnet.checksum(data)

	encoded = encoded
	.. string.char(headerChecksum)
	.. string.char(dataChecksum)
	.. data

	atomnet.sendRaw(address, medium, atomnet.actions.TRANSMIT, encoded)
end

---@param device string
function atomnet.forget(device)
	atomnet.identified[device] = nil

	if atomnet.backtrackingMemory then
		for i=#atomnet.backtrackingMemory, 1, -1 do
			if atomnet.backtrackingMemory[i].device == device then
				table.remove(atomnet.backtrackingMemory, i)
			end
		end
	end
end

function atomnet.forgetAllAfter(timeToDie)
	timeToDie = timeToDie or -math.huge

	local toKill = {}

	local now = computer.uptime()

	for device, data in pairs(atomnet.identified) do
		if (now - data.uptimeAtIdentification) > timeToDie then
			table.insert(toKill, device)
		end
	end

	for _, target in ipairs(toKill) do
		atomnet.forget(target)
	end
end

function atomnet.discover(msg)
	msg = msg or ""
	local msglen = string.pack(">I2", #msg)
	-- Broadcast
	if atomnet.primaryModem then
		atomnet.sendRaw("broadcast", atomnet.mediums.modem, atomnet.actions.DISCOVER, atomnet.addressToBytes(atomnet.address) .. msglen .. msg)
	end
	atomnet.sendRaw("broadcast", atomnet.mediums.tunnel, atomnet.actions.DISCOVER, atomnet.addressToBytes(atomnet.address) .. msglen .. msg)
end

---@param hostname string
---@param timeout? number
---@param enforcePublicKey? boolean
function atomnet.resolveHostSync(hostname, timeout, enforcePublicKey)
	-- to avoid circular require loop
	return require("atomnet.dns").resolveHostSync(hostname, timeout, enforcePublicKey)
end

---@param size integer
---@return string
function atomnet.formatSize(size)
	local units = {"B", "KiB", "MiB", "GiB"}
	local unit = 1

	while unit < #units and size >= 1024 do
		unit = unit + 1
		size = size / 1024
	end
	return string.format("%.2f%s", size, units[unit])
end

-- The maximum amount of data that can be sent.
-- This limit is nota logical limit, thus sending this amount of data
-- in a single write will error due to headers adding too much data.
-- Use recommendedBufferSize() for the size
-- Returns 0 if there is NO available transmission hardware
function atomnet.physicalHardwareLimit()
	local hardwareLimit = math.huge

	if atomnet.primaryModem then
		hardwareLimit = math.min(hardwareLimit, atomnet.primaryModem.maxPacketSize())
	end

	for tunnel in component.list("tunnel", true) do
		hardwareLimit = math.min(hardwareLimit, component.invoke(tunnel, "maxPacketSize"))
	end

	if hardwareLimit == math.huge then return 0 end

	return hardwareLimit
end

-- The recommended amount of data to send at once in a single packet, regardless of protocol
-- This is the minimum packet size limit of all available transmission hardware minus some space for protocol headers.
-- Do note that the size sent via transmission includes AtomNET headers as well.
function atomnet.recommendedBufferSize()
	return math.max(atomnet.physicalHardwareLimit() - 512, 0)
end

return atomnet
