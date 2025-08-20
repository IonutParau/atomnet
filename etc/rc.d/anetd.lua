local fs = require("filesystem")
local atomnet = require("atomnet")
local snp = require("atomnet.snp")
local rcp = require("atomnet.rcp")
local rcps = require("atomnet.rcps")

local function readfile(path)
	local f = io.open(path, "r")
	if not f then return end
	local data = f:read("a")
	f:close()
	return data
end

function start(configPath)
	configPath = configPath or "/etc/atomnet.cfg"

	local configSrc = readfile(configPath)
	if not configSrc then return end

	local config = {}
	assert(load(configSrc, "=" .. configPath, nil, config))()

	if config.address then
		atomnet.address = atomnet.parseAddress(config.address)
	else
		atomnet.address = atomnet.randomAddress()
	end

	if config.dns then
		atomnet.dns = atomnet.parseAddress(config.dns)
	end

	do
		local hostname = readfile("/etc/hostname")
		if hostname then
			atomnet.hostname = hostname
		end
	end

	-- TODO: use /etc/hosts
	if config.hosts then
		for name, ip in pairs(config.hosts) do
			atomnet.hosts[name] = ip
		end
	end

	if config.disableBacktracking then
		atomnet.backtrackingMemory = nil
	end

	if config.disableBroadcasting then
		atomnet.broadcastOnUnknown = false
	end

	if config.disableRouting then
		atomnet.handleRouting = false
	end

	if config.hideFromTraceroute then
		atomnet.includeInTraceroute = false
	end

	if config.snpOpenPorts then
		for _, port in ipairs(config.snpOpenPorts) do
			snp.open(port)
		end
	end

	if config.snpPortAllocationRange then
		snp.setPortAllocationRange(config.snpPortAllocationRange[1], config.snpPortAllocationRange[2])
	end

	-- Finally, start it
	atomnet.init()
	snp.init()
	rcp.init()
	rcps.init()
end

function stop()
	rcps.deinit()
	rcp.deinit()
	snp.deinit()
	atomnet.deinit()
end
