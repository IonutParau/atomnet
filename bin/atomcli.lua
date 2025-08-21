local shell = require("shell")
local component = require("component")
local computer = require("computer")
local event = require("event")
local atomnet = require("atomnet")
local snp = require("atomnet.snp")
local rcp = require("atomnet.rcp")
local rcps = require("atomnet.rcps")
local dns = require("atomnet.dns")
local term = require("term")
local keys = require("keyboard").keys

local args, opts = shell.parse(...)

if args[1] == "init" then
	atomnet.address = atomnet.parseAddress(args[2])
	atomnet.init()
	snp.init()
	rcp.init()
	rcps.init()
	return
end

if args[1] == "set-ip" then
	atomnet.address = atomnet.parseAddress(args[2])
	return
end

if args[1] == "get-ip" then
	print(atomnet.formatAddress(atomnet.address))
	return
end

if args[1] == "set-reliability" then
	atomnet.reliability = (tonumber(args[2]) or 100) / 100
	print((atomnet.reliability * 100) .. "%")
	return
end

if args[1] == "get-reliability" then
	print((atomnet.reliability * 100) .. "%")
	return
end

if args[1] == "set-modem" then
	if args[2] then
		atomnet.switchModem(component.get(args[2], "modem"))
	else
		atomnet.switchModem(nil)
	end
	return
end

if args[1] == "get-modem" then
	if atomnet.primaryModem then
		print(atomnet.primaryModem.address)
		return 0
	end
	print("no modem")
	return
end

if args[1] == "deinit" then
	atomnet.deinit()
	snp.deinit()
	rcp.deinit()
	rcps.deinit()
	return
end

if args[1] == "reload" then
	local ip = atomnet.address
	local hostname = atomnet.hostname
	atomnet.deinit()
	package.loaded["atomnet"] = nil

	snp.deinit()
	package.loaded["atomnet.snp"] = nil

	rcp.deinit()
	package.loaded["atomnet.rcp"] = nil

	rcps.deinit()
	package.loaded["atomnet.rcps"] = nil

	package.loaded["atomnet.dns"] = nil
	package.loaded["atomnet.osp"] = nil
	package.loaded["atomnet.awp"] = nil

	require("atomnet").init()
	require("atomnet").address = ip
	require("atomnet").hostname = hostname
	require("atomnet.snp").init()
	require("atomnet.rcp").init()
	require("atomnet.rcps").init()
	return
end

if args[1] == "hostname" then
	if args[2] then
		atomnet.hostname = args[2]
	else
		print(atomnet.hostname)
	end
	return
end

if args[1] == "rediscover" then
	atomnet.forgetAllAfter()
	atomnet.discover(args[2])
	return
end

if args[1] == "broadcast" then
	if args[2] == "start" then
		atomnet.broadcastOnUnknown = true
		return
	end
	if args[2] == "stop" then
		atomnet.broadcastOnUnknown = false
		return
	end
	if args[2] == "check" then
		print(atomnet.broadcastOnUnknown)
		return
	end
	print("Invalid action. Only start/stop are valid.")
	return
end

if args[1] == "list" then
	if args[2] == "nodes" then
		if not next(atomnet.identified) then
			print("No nodes identified")
		end
		for physAddr, data in pairs(atomnet.identified) do
			local line = string.format("%s (%q, %s, %s, %sm)", atomnet.formatAddress(data.address), data.name, physAddr, data.medium, tostring(data.distance or "?"))
			print(line)
		end
		return 0
	end
	if args[2] == "ranges" then
		print("Listing not implemented")
		return 0
	end
	if args[2] == "dedupes" then
		local total = 0
		for i=1,#atomnet.lastPackets do
			local p = atomnet.lastPackets[i]
			print(string.format("%d. %3.2fs, %dB", i, p.expires, #p.hash))
			total = total + #p.hash
		end
		print("Total = " .. total .. "B")
		return 0
	end
	if args[2] == "backtracking" then
		if not atomnet.backtrackingMemory then
			print("Backtracking is disabled")
			return 0
		end
		if not next(atomnet.backtrackingMemory) then
			print("No backtracked nodes")
			return 0
		end
		for _, backtrack in ipairs(atomnet.backtrackingMemory) do
			local msg = string.format("%s -> %s (%s), MAX %d", atomnet.formatAddress(backtrack.address), backtrack.device, backtrack.medium, backtrack.hop)
			print(msg)
		end
		return 0
	end
	if args[2] == "hosts" then
		if not next(atomnet.hosts) then
			print("No hosts stored")
			return 0
		end
		for host, ip in pairs(atomnet.hosts) do
			print(string.format("%s -> %s", host, atomnet.formatAddress(ip)))
		end
		return
	end
	if args[2] == "keyring" then
		if #rcps.keyringCache == 0 then
			print("No keys cached")
			return
		end
		for _, entry in ipairs(rcps.keyringCache) do
			local fmt = string.format("%s:%d (%s) %s", atomnet.formatAddress(entry.address), entry.port, rcps.encryptionName(entry.algorithm), entry.publicKey and atomnet.hexdump(entry.publicKey) or "not found")
			print(fmt)
		end
		return
	end
	if args[2] == "certs" then
		if #rcps.certificateAuthorities == 0 then
			print("No certs known")
			return
		end
		for _, auth in ipairs(rcps.certificateAuthorities) do
			local fmt = string.format("%s:%d (%s) %s", atomnet.formatAddress(auth.address), auth.port, rcps.encryptionName(auth.encryption), auth.key and atomnet.hexdump(auth.key) or "no key")
			print(fmt)
		end
		return
	end
	if args[2] == "dns" then
		if #dns.servers == 0 then
			print("No DNS provided")
			return
		end
		for _, server in ipairs(dns.servers) do
			local fmt = string.format("%s (%s)", atomnet.formatAddress(server.address), rcps.encryptionName(server.encryption))
			print(fmt)
		end
		return
	end
	if args[2] == "domains" then
		if #dns.cache == 0 then
			print("No domains cached")
			return
		end
		for _, entry in ipairs(dns.cache) do
			local fmt = string.format("%s -> %s", entry.hostname, entry.address == 0 and "not found" or atomnet.formatAddress(entry.address))
			print(fmt)
		end
		return
	end
	print("Invalid argument to list. Valid ones are: nodes, ranges, backtracking, dedupes, hosts, keyring, certs, dns, domains")
	return 0
end

if args[1] == "clear-domains" then
	dns.cache = {}
	return
end

if args[1] == "add-dns" then
	local addr = atomnet.resolveHostSync(args[2])
	local cert = assert(rcps.encryption[args[3]], "bad encryption")
	---@type dns.server
	local server = {
		address = addr,
		encryption = cert,
	}
	table.insert(dns.servers, server)
	return
end

if args[1] == "rm-dns" then
	local addr = atomnet.resolveHostSync(args[2])

	for i=1, #dns.servers do
		if dns.servers[i].address == addr then
			table.remove(dns.servers, i)
			return
		end
	end
	print("no such DNS")
	return
end

if args[1] == "add-cert" then
	local addr = atomnet.resolveHostSync(args[2])
	local port = tonumber(opts.port) or rcps.stdCertificatePort
	---@type rcps.encryption
	local encryption = rcps.encryption.none

	if opts.encryption then
		encryption = assert(rcps.encryption[opts.encryption], "bad encryption")
	end

	---@type string?
	local key = nil

	-- TODO: some way to read the damn key

	local version = tonumber(opts.version) or rcps.currentCertVersion
	local timeout = tonumber(opts.timeout) or 2

	---@type rcps.authority
	local authority = {
		encryption = encryption,
		address = addr,
		port = port,
		version = version,
		timeout = timeout,
		key = key,
	}

	table.insert(rcps.certificateAuthorities, authority)
	return
end

if args[1] == "rm-cert" then
	local addr = atomnet.resolveHostSync(args[2])

	for i=1,#rcps.certificateAuthorities do
		if rcps.certificateAuthorities[i].address == addr then
			table.remove(rcps.certificateAuthorities, i)
			return
		end
	end
	return
end

if args[1] == "clear-keys" then
	rcps.keyringCache = {}
	return
end

if args[1] == "get-key" then
	local addr = atomnet.resolveHostSync(args[2])
	local port = tonumber(args[3])
	assert(port, "bad port")
	local encryption = rcps.encryption.none

	if opts.encryption then
		encryption = assert(rcps.encryption[opts.encryption], "bad encryption")
	end
	local key = rcps.downloadKey(addr, port, encryption)
	if key then
		print(atomnet.hexdump(key))
		return
	end
	print("no key found")
	return
end

if args[1] == "set-balance" then
	local n = tonumber(args[2])
	assert(n, "bad number")
	n = math.floor(n)
	atomnet.maxLoadBalancingNodes = n
	return
end

if args[1] == "get-balance" then
	print(atomnet.maxLoadBalancingNodes)
	return
end

if args[1] == "backtrack" then
	if args[2] == "start" then
		atomnet.backtrackingMemory = {}
		return 0
	end
	if args[2] == "stop" then
		atomnet.backtrackingMemory = nil
		return 0
	end
	print("Invalid operation: " .. args[2])
	return 0
end

if args[1] == "logs" then
	local gpu = component.gpu

	local w, h = gpu.getResolution()

	local off = math.max(#atomnet.logs - h, 0)

	while true do
		local ev = {event.pull()}

		for i=1,h do
			gpu.fill(1, i, w, 1, " ")
			gpu.set(1, i, atomnet.logs[i + off] or "")
		end

		if ev[1] == "interrupted" then break end

		if ev[1] == "key_down" then
			if ev[4] == keys.q then
				break
			end

			if ev[4] == keys.up then
				off = off - 1
				if off < 0 then off = 0 end
			end

			if ev[4] == keys.down then
				off = off + 1
			end
		end
	end

	term.clear()
	return
end

if args[1] == "send" then
	local ip = atomnet.resolveHostSync(args[2])
	local data = args[3]
	local protocol = tonumber(opts.protocol) or 0
	local hops = tonumber(opts.hops)
	atomnet.sendTo(ip, protocol, data, hops)
	return
end

if args[1] == "chat" then
	-- Super basic direct chat
	local ips = {}

	for i=2,#args do
		table.insert(ips, atomnet.resolveHostSync(args[i]))
	end

	if #ips == 0 then
		print("You must supply at least 1 AN address")
		return -1
	end

	print("Beginning chat connected to " .. #ips .. " devices.")
	print("Press tab to write a message. Empty messages are ignored")
	print("Press Ctrl-C to escape")

	while true do
		local e = {event.pull()}

		if e[1] == "interrupted" then break end

		if e[1] == "atom_msg" then
			local _, src, protocol, data = table.unpack(e)
			if protocol == 0x00 then
				local allowed = false

				for i=1,#ips do
					if ips[i] == src then
						allowed = true
						break
					end
				end

				if allowed then
					local line = string.format("%s > %s", atomnet.formatAddress(src), data)
					print(line)
				end
			end
		end

		if e[1] == "key_down" then
			if e[4] == keys.tab then
				io.write(atomnet.formatAddress(atomnet.address), " > ")
				io.flush()
				local line = io.read("l")

				for i=1,#ips do
					atomnet.sendTo(ips[i], 0x00, line)
				end
			end
		end
	end
	return
end

if args[1] == "ping" then
	local dest = atomnet.resolveHostSync(args[2])

	local pingSize = tonumber(opts.size) or 64

	local sent = 0
	local received = 0
	local keepGoing = true

	while keepGoing do
		local randomData = ""
		for _=1,pingSize do
			randomData = randomData .. string.char(math.random(0, 255))
		end
		atomnet.ping(dest, randomData)
		sent = sent + 1
		local start = computer.uptime()
		while true do
			local e = {event.pull(1)}
			if e[1] == "interrupted" then
				sent = sent - 1 -- undo 1 send
				keepGoing = false
				break
			end
			if e[1] == "atom_pong" then
				if e[2] == dest then
					local data = e[3]
					local stop = computer.uptime()
					local dataMsg = "corrupted data"
					if data == randomData then
						received = received + 1
						dataMsg = #data .. " bytes"
					end
					local msg = string.format("%s in %.3fs", dataMsg, stop - start)
					print(msg)
					break
				end
			end
			if not e[1] then
				print("timeout")
				break
			end
		end
	end

	local msg = string.format("%d packets sent, %d received (%.2f%% loss)", sent, received, (sent - received) / sent * 100)
	print(msg)
	return
end

if args[1] == "dm-upload" then
	local dest = atomnet.resolveHostSync(args[2])
	local path = assert(args[3])

	local f = assert(io.open(path, "rb"))
	local blocksize = tonumber(opts.blocksize) or 4096

	while true do
		local block = f:read(blocksize)
		if not block then
			atomnet.sendTo(dest, 0x00, "")
			break
		end
		if #block > 0 then
			atomnet.sendTo(dest, 0x00, block)
			print("Uploaded " .. #block .. "B")
		end
	end

	f:close()
	return
end

if args[1] == "dm-download" then
	local dest = atomnet.resolveHostSync(args[2])
	local path = assert(args[3])

	local f = assert(io.open(path, "wb"))

	while true do
		local e = {event.pull(5)}

		if (e[1] == nil) or (e[1] == "interrupted") then
			break
		end

		if e[1] == "atom_msg" and e[2] == dest and e[3] == 0x00 then
			if e[4] == "" then break end
			f:write(e[4])
			f:flush()
			print("Downloaded " .. #e[4] .. "B")
		end
	end

	f:close()
	return
end

if args[1] == "set-host" then
	local host = args[2]
	local ip = nil
	if args[3] then ip = atomnet.resolveHostSync(args[3]) end

	atomnet.hosts[host] = ip
	return
end

if args[1] == "resolve" then
	local ip = atomnet.resolveHostSync(args[2], tonumber(opts.timeout), opts.s)
	print(atomnet.formatAddress(ip))
	return
end

if args[1] == "traceroute" then
	local ip = atomnet.resolveHostSync(args[2])
	atomnet.sendTo(ip, atomnet.protocols.NetworkCheck, string.char(2, 0, 0))

	local times = tonumber(opts.times) or 3
	local maxtime = tonumber(opts.timeout) or 3

	for _=1, times do
		local start = computer.uptime()
		while true do
			local elapsed = computer.uptime() - start
			if elapsed >= maxtime then break end
			local ev, src, ips = event.pull(maxtime - elapsed)

			if ev == "atom_traceroute" and src == ip then
				for i, ip in ipairs(ips) do
					print(i .. ". " .. atomnet.formatAddress(ip))
				end
				return
			end

			if ev == "interrupted" then break end

			if not ev then
				print("timed out")
				return
			end
		end
	end

	return
end

if args[1] == "routing" then
	if args[2] == "block" then
		atomnet.handleRouting = false
		return
	end
	if args[2] == "allow" then
		atomnet.handleRouting = true
		return
	end
	return
end

if args[1] == "config" then
	io.write("Address (blank for random) > ")
	local addrStr = io.read("l")
	if not addrStr then return end

	io.write("Hostname (blank for default) > ")
	local hostnameStr = io.read("l")
	if not hostnameStr then return end

	io.write("Disable routing? [y/N] ")
	local disableRouting = io.read("l")
	if not disableRouting then return end

	io.write("Disable backtracking? [y/N] ")
	local disableBacktracking = io.read("l")
	if not disableBacktracking then return end

	io.write("Disable broadcasting? [y/N] ")
	local disableBroadcasting = io.read("l")
	if not disableBroadcasting then return end

	io.write("Hide from traceroute? [y/N] ")
	local hideFromTraceroute = io.read("l")
	if not hideFromTraceroute then return end

	io.write("DNS address (blank for no DNS) > ")
	local dnsStr = io.read("l")
	if not dnsStr then return end

	local config = {}

	if addrStr == "" then
		config.address = atomnet.formatAddress(atomnet.randomAddress())
	else
		config.address = addrStr
	end

	if #dnsStr > 0 then
		config.dns = dnsStr
	end

	if #hostnameStr > 0 then
		local hostnameFile = assert(io.open("/etc/hostname", "w"))
		hostnameFile:write(hostnameStr)
		hostnameFile:close()
	end

	if disableRouting:lower():sub(1,1) == "y" then
		config.disableRouting = true
	end

	if disableBacktracking:lower():sub(1,1) == "y" then
		config.disableBacktracking = true
	end

	if hideFromTraceroute:lower():sub(1,1) == "y" then
		config.hideFromTraceroute = true
	end

	if disableBroadcasting:lower():sub(1,1) == "y" then
		config.disableBroadcasting = true
	end

	local serialization = require("serialization")

	local configFile = assert(io.open("/etc/atomnet.cfg", "w"))

	for k, v in pairs(config) do
		configFile:write(k, " = ", serialization.serialize(v), "\n")
	end

	configFile:close()

	return
end

if args[1] == "test-rcp" then
	local addr = atomnet.resolveHostSync(args[2])
	local data = args[3]

	print(rcp.writeAsync(addr, 49, 48, data))
	os.execute("dmesg")
	return
end

if args[1] == "wiretap" then
	local peers = {}
	for i=2,#args do
		table.insert(peers, atomnet.addressToBytes(atomnet.resolveHostSync(args[i])))
	end

	print("Spying on " .. #peers .. " peer(s)")

	local function isPeer(addrBytes)
		for i=1,#peers do
			if peers[i] == addrBytes then
				return true
			end
		end
		return false
	end

	local randsSeen = {}

	local function isRandSeen(randID)
		for i=1,#randsSeen do
			if randsSeen[i] == randID then
				return true
			end
		end
		return false
	end

	local function wiretap(packet)
		if type(packet) ~= "string" then return end

		if packet:sub(1, 5) ~= "ATOM\0" then return end
		if packet:sub(7, 8) ~= "\0\0" then return end -- not transmit

		local transmission = packet:sub(9)
		local srcBytes = transmission:sub(1, 4)
		local destBytes = transmission:sub(5, 8)
		local randID = transmission:sub(13, 16)

		if isRandSeen(randID) then return end
		if not isPeer(srcBytes) then return end
		if not isPeer(destBytes) then return end
		table.insert(randsSeen, randID)
		while #randsSeen > 128 do table.remove(randsSeen, 1) end

		local protocol = transmission:byte(17)
		local len = string.unpack(">I2", transmission, 19)
		local data = string.sub(transmission, 23, 22 + len)

		local protocolNames = {
			[0x00] = "DM", -- direct message
			[0x01] = "NC", -- network check
			[0x02] = "RHS", -- remote hosts source
			[0x03] = "SNP", -- segmented node protocol
			[0x04] = "RCP", -- remote communication protocol
		}

		local protocolName = protocolNames[protocol] or "unknown"

		local src = atomnet.formatAddress(atomnet.addressFromBytes(srcBytes))
		local dest = atomnet.formatAddress(atomnet.addressFromBytes(destBytes))

		local f = string.format("(%s) %s -> %s: (%dB) %q", protocolName, src, dest, #data, data)
		print(f)
	end

	while true do
		local e = {event.pull()}

		if e[1] == "interrupted" then break end

		if e[1] == "modem_message" then
			wiretap(e[6])
		end
	end
	return
end

local RCPS_TEST_PORT = 81

if args[1] == "rcps-connect" then
	local ip = atomnet.resolveHostSync(args[2])
	local enc = rcps.encryption.none
	local serverKey = nil

	if opts.encryption then
		local k = rcps.encryption[opts.encryption]
		assert(k, "unknown encryption")
		enc = k

		if opts.serverKey then
			serverKey = atomnet.hexload(opts.serverKey)
		end

		if opts.serverKeyFile then
			local f = assert(io.open(opts.serverKeyFile, "r"))
			local data = f:read("a")
			f:close()
			assert(data, "failed to load file")
			serverKey = atomnet.hexload(data)
		end
	end

	print("Connecting...")
	local connected = false
	local conn = rcps.connect(ip, RCPS_TEST_PORT, {
		connected = function(sesh, encryption)
			connected = true
			print("Connection established.")
			if encryption ~= rcps.encryption.none then
				print("Server public key:", atomnet.hexdump(sesh.acceptedServerKey))
			end
		end,
		disconnected = function(sesh, code, msg)
			connected = false
			print("Disconnected.")
			event.push("rcps_test_gone")
		end,
		sent = function()
			return false, ""
		end,
		responded = function(sesh, packetID, accepted, data)
			event.push("rcps_test_resp", accepted, data)
		end,
		timeout = function(sesh, packetID)
			event.push("rcps_test_timeout")
		end,
	}, {encryption = enc, serverPublicKey = serverKey})
	while true do
		local e = {event.pull()}
		if e[1] == "interrupted" then break end
		if e[1] == "rcps_test_gone" then break end

		if e[1] == "rcps_test_resp" then
			print("Server response:", e[2], e[3])
		end

		if e[1] == "rcps_test_timeout" then
			print("Server timeout")
		end

		if e[1] == "key_down" and e[4] == keys.tab then
			local l = io.read("l")
			if l then
				rcps.sendAsync(conn, l)
			end
		end
	end
	if connected then
		print("Disconnecting...")
		rcps.disconnect(conn, rcps.exit.closed, "closed")
	end
	return
end

if args[1] == "rcps-serve" then
	print("Opening server...")
	---@type rcps.serverKeys
	local serverKeys = {}

	if rcps.encryptionSupported(rcps.encryption.stdencrypt256) then
		serverKeys.stdencrypt256PublicKey, serverKeys.stdencrypt256PrivateKey = rcps.generateKeyPair(rcps.encryption.stdencrypt256)
		local dumped = atomnet.hexdump(serverKeys.stdencrypt256PublicKey)
		print("STDENCRYPT256 PUBLIC KEY:", dumped)
		local f = assert(io.open("keyfile.txt", "w"))
		f:write(dumped)
		f:close()
	end

	local server = rcps.open(RCPS_TEST_PORT, {
		connected = function(sesh, encryption)
			local src = atomnet.formatAddress(sesh.src)
			local f = string.format("Connection from %s:%d with %s", src, sesh.srcPort, rcps.encryptionName(encryption))
			print(f)
		end,
		disconnected = function(sesh, code, msg)
			local src = atomnet.formatAddress(sesh.src)
			local f = string.format("%s:%d disconnected", src, sesh.srcPort)
			print(f)
		end,
		sent = function(sesh, data)
			local src = atomnet.formatAddress(sesh.src)
			local f = string.format("%s:%d sent us %q", src, sesh.srcPort, data)
			print(f)
			return true, data
		end,
		-- we don't send shit
		responded = function(sesh)
		end,
		timeout = function(sesh)
		end,
	}, serverKeys)
	event.pull("interrupted")
	print("Closing server...")
	rcps.close(server)
	return
end

return 0
