local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local computer = require("computer")

--[[

// DNS protocol
// big endian

struct dns_request {
	uint8_t version = 0;
	char hostname[]; // NULL-terminated
};

// accepted ack for version 0
// rejected acks are for internal errors
struct dns_response_v0 {
	uint8_t indirect; // if 1, the address is another DNS server to ask
	uint32_t address; // 0 if not found
	uint8_t encryption; // if indirect is 1, this is the encryption to use on the other DNS server. See rcps.encryption
};

]]

local dns = {}

dns.port = 53

---@class dns.server
---@field address atomnet.address
---@field encryption rcps.encryption

---@type dns.server[]
dns.servers = {}

---@class dns.cacheEntry
---@field hostname string
---@field address integer

---@type dns.cacheEntry[]
dns.cache = {}

dns.notFound = 0

---@param hostname string
---@param timeout? number
---@param enforcePublicKey? boolean
---@return atomnet.address
function dns.resolveHostSync(hostname, timeout, enforcePublicKey)
	if atomnet.isValidAddress(hostname) then
		return atomnet.parseAddress(hostname)
	end

	if atomnet.hosts[hostname] then
		return atomnet.hosts[hostname]
	end

	local notFoundErr = "unresolved hostname: " .. hostname
	for _, entry in ipairs(dns.cache) do
		if entry.hostname == hostname then
			if entry.address == 0 then
				error(notFoundErr)
			end
			return entry.address
		end
	end

	timeout = timeout or 5

	local deadline = computer.uptime() + timeout

	local function timeExceeded()
		return computer.uptime() >= deadline
	end

	local function timeLeft()
		return deadline - computer.uptime()
	end

	for _, server in ipairs(dns.servers) do
		local addr, enc = server.address, server.encryption
		while true do
			if timeExceeded() then
				error("timeout")
			end

			local key = rcps.downloadKey(addr, dns.port, enc)

			if key or not enforcePublicKey then
				local conn = rcps.connectSync(addr, dns.port, rcps.nothingTable, timeLeft(), {
					encryption = enc,
					serverPublicKey = key,
				})

				if conn then
					local ok, msg = rcps.send(conn, string.char(0) .. hostname .. string.char(0), timeLeft())
					msg = msg or ""

					if ok then
						if msg:byte(1, 1) == 0 then
							rcps.disconnect(conn, rcps.exit.closed, "")
							local a = atomnet.addressFromBytes(msg:sub(2, 5))
							table.insert(dns.cache, {
								hostname = hostname,
								address = a,
							})
							if a == 0 then
								break
							end
							return a
						end
						if msg:byte(1, 1) == 1 then
							addr = atomnet.addressFromBytes(msg:sub(2, 5))
							enc = msg:byte(6, 6)
						end
					end

					rcps.disconnect(conn, rcps.exit.closed, "")
				end
			end
		end
	end

	error(notFoundErr)
end

return dns
