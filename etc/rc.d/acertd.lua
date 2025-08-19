local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")
local serial = require("serialization")
local fs = require("filesystem")

--[[
// Big endian

// Basic request
struct acert_req {
	uint8_t version = 0;
	uint8_t encryption; // see rcps.encryption
	uint16_t port;
	uint32_t address;
};

// rejected if not found

// Version 0 response
struct acert_respv0 {
	char key[]; // every byte is key byte
}

]]

local certPort = rcps.stdCertificatePort
---@type rcps.serverKeys
local keys = {}

---@param address integer
---@param port integer
---@param encryption rcps.encryption
local function hashInfo(address, port, encryption)
	return string.char(encryption) .. string.pack(">I2>I4", port, address)
end

---@type table<string, string>
local records = {}

local configPath = "/etc/acert.lon"

-- TODO: fix theoretical attack where connections are open but no request is made

local function cleanup()
	rcps.close(certPort)
end

local function saveConfig()
	local data = serial.serialize {
		keys = keys,
		records = records,
	}
	local f = assert(io.open(configPath, "w"))
	f:write(data)
	f:close()
end

local function loadConfig()
	if fs.exists(configPath) then
		local f = assert(io.open(configPath, "r"))
		local data = f:read("a")
		f:close()

		local conf = serial.unserialize(data)

		keys = conf.keys
		records = conf.records
	end

	if rcps.encryptionSupported(rcps.encryption.stdencrypt256) and not keys.stdencrypt256PublicKey then
		-- make the key pair
		keys.stdencrypt256PublicKey, keys.stdencrypt256PrivateKey = rcps.generateKeyPair(rcps.encryption.stdencrypt256)
	end
end

---@type rcps.vtable
local certVTable = {
	connected = function(sesh, encryption) end,
	disconnected = function(sesh, exit, msg) end,
	sent = function (sesh, data)
		if data:byte(1, 1) == 0 then
			local hash = data:sub(2, 8)
			if not records[hash] then
				return false, ""
			end
			-- we disconnect instantly cuz it doesn't matter to us anymore
			rcps.disconnect(sesh, rcps.exit.closed, "")
			return true, records[hash]
		end
		return false, ""
	end,
	timeout = function (sesh, packetID) end,
	responded = function (sesh, packetID, accepted, response) end,
}

local function setup()
	rcps.open(certPort, certVTable, keys)
end

function start()
	cleanup()
	loadConfig()
	setup()
end

function stop()
	cleanup()
end

function store()
	saveConfig()
end

function storeKey(address, port, encryption, keyFile)
	address = atomnet.resolveHostSync(address)
	encryption = assert(rcps.encryption[encryption], "invalid encryption")

	local f = assert(io.open(keyFile, "r"))
	local key = f:read("a")
	f:close()

	records[hashInfo(address, port, encryption)] = key
end

function forgetKey(address, port, encryption)
	address = atomnet.resolveHostSync(address)
	encryption = assert(rcps.encryption[encryption], "invalid encryption")

	records[hashInfo(address, port, encryption)] = nil
end

function printKey()
	print("STDENCRYPT-256")
	print(atomnet.hexdump(keys.stdencrypt256PublicKey))
end

function writeKey(path)
	local f = assert(io.open(path, "w"))
	f:write(serial.serialize({
		stdencrypt256 = atomnet.hexdump(keys.stdencrypt256PublicKey),
	}))
	f:close()
end
