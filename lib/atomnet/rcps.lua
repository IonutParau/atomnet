-- RCP sessions
-- This protocol allows plaintext or encrypted sessions over RCP.
-- It connects in 1 RCP packet/response, including for encryption,
-- and to verify connections are alive, will use heartbeats (which may also be encrypted to ensure we are still connected to the same session)

local atomnet = require("atomnet")
local rcp = require("atomnet.rcp")
local event = require("event")
local computer = require("computer")
local component = require("component")

--[[
// big endian

struct rcps_connect {
	uint8_t magic = 0;
	uint8_t encryption;
	// encryption stuff
	union {
		char stdEncryptPK[]; // rest of packet
	};
};

// server ack to rcps_connect
struct rcps_connected {
	// encryption stuff
	union {
		struct {
			char publicKey[]; // rest of packet
		} stdEncrypt;
	};
};

// all stdencrypt packets and acks are encoded like this if encryption is used (before encryption)
struct rcps_stdencrypt_data {
	// true bytes
	uint128_t randomIV;
	// these are the actual bytes that are encrypted with the stdencrypt algorithm ofc
	uint32_t packetID; // in case of replay attack
	uint8_t prefixSize; // random amount of bytes
	uint8_t prefix[prefixSize]; // random bytes, strengthens encryption
	uint8_t data[]; // rest of encrypted data packet
};

// valid client-to-server and server-to-client
struct rcps_disconnect {
	uint8_t magic = 1;
	uint8_t exitCode; // see rcps.exit
	uint8_t msg[];
};

struct rcps_msg {
	uint8_t magic = 2;
	uint8_t data[];
};

enum rcps_encryption {
	NO_ENCRYPT = 0,
	// not yet implemented
	STD_ENCRYPT = 1, // 256-bit ECDH key exchange to get the 256-bit shared key that is MD5'd into a 128-bit hash and then encrypted with AES-128 (0 byte IV)
};
]]

---@class rcps.vtable
---@field connected fun(sesh: rcps.session, encryption: rcps.encryption)
---@field disconnected fun(sesh: rcps.session, exitCode: rcps.exit, msg: string)
--- Returns whether it is accepted and the response
---@field sent fun(sesh: rcps.session, data: string): boolean, string
---@field responded fun(sesh: rcps.session, packetID: string, accepted: boolean, response: string)
---@field timeout fun(sesh: rcps.session, packetID: string)

---@class rcps.session
---@field serverSide boolean
---@field encryption rcps.encryption
---@field privateKey unknown
---@field publicKey unknown
---@field sharedKey string
---@field acceptedServerKey? string
---@field src integer
---@field srcPort integer
---@field port integer
---@field state "connecting"|"connected"|"closed"
---@field data any
---@field vtable rcps.vtable

local rcps = {}

---@enum rcps.exit
rcps.exit = {
	success = 0x00,
	timeout = 0x01, -- something timed out
	internal = 0x02, -- internal error
	subprotocol = 0x03, -- subprotocol error, likely a bad header
	impostor = 0x04, -- public key not recognized
	closed = 0x05,
}

---@type rcps.session[]
local _CONNS = {}

---@class rcps.serverKeys
---@field stdencrypt256PublicKey? string
---@field stdencrypt256PrivateKey? string

---@class rcps.server
---@field vtable rcps.vtable
---@field keys rcps.serverKeys

---@type table<integer, rcps.server>
local _SRVS = {}

---@enum rcps.encryption
rcps.encryption = {
	none = 0,
	stdencrypt256 = 1,
}

---@param encryption rcps.encryption
function rcps.encryptionSupported(encryption)
	if encryption == rcps.encryption.none then
		return true
	end
	if encryption == rcps.encryption.stdencrypt256 then
		if not component.isAvailable("data") then return false end
		local data = component.data
		return data.random ~= nil and data.encrypt ~= nil and data.ecdh ~= nil and data.md5 ~= nil
	end
	return false
end

--- This may not always be supported, but is the encryption method
--- that is recommended by this version of rcps.
---@return rcps.encryption
function rcps.recommendedEncryption()
	return rcps.encryption.stdencrypt256
end

---@param encryption rcps.encryption
---@return string?
function rcps.encryptionName(encryption)
	if encryption == rcps.encryption.none then
		return "none"
	end
	if encryption == rcps.encryption.stdencrypt256 then
		return "StdEncrypt-256"
	end
end

---@class rcps.keyringEntry
---@field address atomnet.address
---@field port integer
---@field algorithm rcps.encryption
---@field publicKey? string
---@field expiration number

---@type rcps.keyringEntry[]
rcps.keyringCache = {}

rcps.stdCertificatePort = 323

rcps.currentCertVersion = 0

---@class rcps.authority
---@field version integer
---@field address atomnet.address
---@field port integer
---@field encryption rcps.encryption
---@field key string?
---@field timeout number

---@type rcps.authority[]
rcps.certificateAuthorities = {}

rcps.keyTimeout = 30*60

---@param address atomnet.address
---@param port integer
---@param algorithm rcps.encryption
---@return string?
function rcps.downloadKey(address, port, algorithm)
	if algorithm == rcps.encryption.none then return end
	for i=#rcps.keyringCache, 1, -1 do
		local cache = rcps.keyringCache[i]
		if cache.address == address and cache.port == port and cache.algorithm == algorithm then
			if computer.uptime() > cache.expiration then
				table.remove(rcps.keyringCache, i)
				break
			end
			return cache.publicKey
		end
	end

	for _, auth in ipairs(rcps.certificateAuthorities) do
		local k = rcps.downloadKeyFromAuth(auth, address, port, algorithm)
		if k then return k end
	end

	-- not found, cache that it is not found
	local entry = {
		algorithm = algorithm,
		port = port,
		address = address,
		publicKey = nil,
		expiration = computer.uptime() + rcps.keyTimeout,
	}

	table.insert(rcps.keyringCache, entry)
end

---@param auth rcps.authority
---@param address atomnet.address
---@param port integer
---@param algorithm rcps.encryption
---@return string?
function rcps.downloadKeyFromAuth(auth, address, port, algorithm)
	if algorithm == rcps.encryption.none then return end
	local conn = rcps.connectSync(auth.address, auth.port, rcps.nothingTable, auth.timeout, {
		encryption = auth.encryption,
		serverPublicKey = auth.key,
	})

	if not conn then
		return
	end

	local ok, key = rcps.send(conn, string.char(auth.version, algorithm) .. string.pack(">I2>I4", port, address))

	if not ok then
		rcps.disconnect(conn, rcps.exit.closed, "")
		return
	end

	---@type rcps.keyringEntry
	local entry = {
		algorithm = algorithm,
		port = port,
		address = address,
		publicKey = key or "",
		expiration = computer.uptime() + rcps.keyTimeout,
	}

	table.insert(rcps.keyringCache, entry)

	rcps.disconnect(conn, rcps.exit.closed, "")
	return key
end

---@param src atomnet.address
---@param srcPort integer
---@param port integer
---@return rcps.session?
local function getConnection(src, srcPort, port)
	for i=1,#_CONNS do
		local conn = _CONNS[i]
		if conn.src == src and conn.srcPort == srcPort and conn.port == port then
			return conn
		end
	end
end

---@param conn rcps.session
---@param data string
---@return string
local function encryptMessage(conn, data)
	if conn.state == "connecting" then return data end -- can't encrypt if its not connected
	if conn.encryption == rcps.encryption.stdencrypt256 then
		local packetID = atomnet.randomPacketID()
		local prefixSize = math.random(1, 255)
		local prefix = component.data.random(prefixSize)
		local iv = component.data.random(16)
		local entireThing = iv .. packetID .. string.char(prefixSize) .. prefix .. data
		return component.data.encrypt(entireThing, conn.sharedKey, iv)
	end
	return data
end

---@param conn rcps.session
---@param data string
---@param forced boolean
---@return string
local function decryptMessage(conn, data, forced)
	if conn.state ~= "connected" and not forced then return data end -- can't encrypt if its not connected
	if conn.encryption == rcps.encryption.stdencrypt256 then
		-- TODO: check packet ID for replay attacks
		local iv = data:sub(1, 16)
		local entireThing = component.data.decrypt(data:sub(17), conn.sharedKey, iv)
		local prefixSize = entireThing:byte(5, 5)
		return entireThing:sub(6 + prefixSize)
	end
	return data
end

---@param port integer
---@return rcp.middleware
local function getMiddleware(port)
	return function(src, srcPort, data)
		local server = _SRVS[port]
		local conn = getConnection(src, srcPort, port)

		if server and not conn then
			if data:byte(1, 1) == 0 then
				-- we are connecting now!!!!
				local encryption = data:byte(2, 2)

				-- no encryption is supported so like...
				if not rcps.encryptionSupported(encryption) then
					return true
				end

				conn = {
					serverSide = true,
					data = nil,
					port = port,
					src = src,
					srcPort = srcPort,
					state = "connected",
					vtable = server.vtable,
					encryption = encryption,
					privateKey = nil,
					publicKey = nil,
					sharedKey = "",
					acceptedServerKey = "",
				}

				local respData = ""

				-- Compute the shared key, and IV
				if encryption == rcps.encryption.stdencrypt256 then
					local serverPublic, serverPrivate
					local serializedPublic = ""

					if server.keys.stdencrypt256PrivateKey then
						serverPublic = component.data.deserializeKey(server.keys.stdencrypt256PublicKey, "ec-public")
						serverPrivate = component.data.deserializeKey(server.keys.stdencrypt256PrivateKey, "ec-private")
						serializedPublic = server.keys.stdencrypt256PublicKey
					else
						serverPublic, serverPrivate = component.data.generateKeyPair(256)
						serializedPublic = serverPublic.serialize()
					end

					local theirPublic = component.data.deserializeKey(data:sub(3), "ec-public")

					local sharedKey = component.data.md5(component.data.ecdh(serverPrivate, theirPublic))
					conn.sharedKey = sharedKey

					respData = assert(serializedPublic)
				end

				table.insert(_CONNS, conn)

				conn.vtable.connected(conn, encryption)

				return false, respData
			end
		end

		if conn then
			data = decryptMessage(conn, data)

			if data:byte(1, 1) == 2 then
				-- we got sent a message!!!!!
				local accepted, resp = conn.vtable.sent(conn, data:sub(2))
				return not accepted, encryptMessage(conn, resp)
			end

			if data:byte(1, 1) == 1 then
				-- shit they want to disconnect!!!!!
				local code = data:byte(2, 2)
				local msg = data:sub(3)
				rcps.disconnect(conn, code, msg, true)
				return false
			end
		end

		return true, "bad packet" -- rejected, unknown shit
	end
end

---@param encryption rcps.encryption
--- Returns the public first, private second!
---@return string, string
function rcps.generateKeyPair(encryption)
	assert(rcps.encryptionSupported(encryption), "unsupported encryption")
	if encryption == rcps.encryption.stdencrypt256 then
		local data = component.data
		local public, private = data.generateKeyPair(256)
		return public.serialize(), private.serialize()
	end

	return "", ""
end

---@param src atomnet.address
---@param srcPort integer
---@param port integer
---@param data string
---@param packetID string
local function rcp_ack(_, src, srcPort, port, data, packetID)
	local conn = getConnection(src, srcPort, port)
	if not conn then return end
	if conn.state == "connecting" then
		-- finalize encryption
		if conn.encryption == rcps.encryption.stdencrypt256 then
			-- extract very important data
			local encodedServerKey = data
			if conn.acceptedServerKey and conn.acceptedServerKey ~= encodedServerKey then
				-- don't even care to send, we don't respect impersonators
				rcps.disconnect(conn, rcps.exit.impostor, "", true)
				return
			end
			-- so you can check what it is and store it
			conn.acceptedServerKey = encodedServerKey
			local serverPublic = component.data.deserializeKey(encodedServerKey, "ec-public")
			conn.sharedKey = component.data.md5(component.data.ecdh(conn.privateKey, serverPublic))
		end
		conn.state = "connected"
		conn.vtable.connected(conn, conn.encryption)
		return
	end
	data = decryptMessage(conn, data)
	conn.vtable.responded(conn, packetID, true, data)
end

---@param src atomnet.address
---@param srcPort integer
---@param port integer
---@param data string
---@param packetID string
local function rcp_rejected(_, src, srcPort, port, data, packetID)
	local conn = getConnection(src, srcPort, port)
	if not conn then return end
	if conn.state == "connecting" then
		rcps.disconnect(conn, rcps.exit.timeout, "", true)
		return
	end
	data = decryptMessage(conn, data)
	conn.vtable.responded(conn, packetID, false, data)
end

---@param src atomnet.address
---@param srcPort integer
---@param port integer
---@param packetID string
local function rcp_timeout(_, src, srcPort, port, packetID)
	local conn = getConnection(src, srcPort, port)
	if not conn then return end
	if conn.state == "connecting" then
		rcps.disconnect(conn, rcps.exit.timeout, "", true)
		return
	end
	conn.vtable.timeout(conn, packetID)
end

function rcps.init()
	event.listen("rcp_ack", rcp_ack)
	event.listen("rcp_rejected", rcp_rejected)
	event.listen("rcp_timeout", rcp_timeout)
end

function rcps.deinit()
	event.ignore("rcp_ack", rcp_ack)
	event.ignore("rcp_rejected", rcp_rejected)
	event.ignore("rcp_timeout", rcp_timeout)
end

---@param port? integer
---@param vtable rcps.vtable
---@param keys? rcps.serverKeys
---@return integer
function rcps.open(port, vtable, keys)
	port = port or rcp.findAvailablePort()
	port = rcp.open(port, getMiddleware(port))
	keys = keys or {}
	_SRVS[port] = {
		vtable = vtable,
		keys = keys,
	}
	return port
end

---@param port integer
function rcps.close(port)
	rcp.close(port)
end

---@class rcps.connectOpts
---@field port? integer
---@field encryption rcps.encryption
---@field privateKey? string
---@field publicKey? string
---@field serverPublicKey? string

---@param dest atomnet.address
---@param destPort integer
---@param vtable rcps.vtable
---@param opts? rcps.connectOpts
---@return rcps.session
function rcps.connect(dest, destPort, vtable, opts)
	opts = opts or {
		encryption = rcps.encryption.none,
	}

	assert(rcps.encryptionSupported(opts.encryption), "unsupported encryption")

	local internalPort = opts.port or rcp.findAvailablePort()
	internalPort = rcp.open(internalPort, getMiddleware(internalPort))

	---@type rcps.session
	local conn = {
		vtable = vtable,
		src = dest,
		srcPort = destPort,
		port = internalPort,
		state = "connecting",
		serverSide = false,
		data = nil,
		encryption = opts.encryption,
		privateKey = nil,
		publicKey = nil,
		sharedKey = "",
		acceptedServerKey = nil,
	}

	if opts.encryption == rcps.encryption.stdencrypt256 then
		conn.acceptedServerKey = opts.serverPublicKey
		if opts.publicKey or opts.privateKey then
			-- we need the whole pair, though technically if data card API was better
			-- we only would need privateKey
			-- since publicKey is g^A mod p, where A is the private key
			assert(opts.publicKey, "missing public key")
			assert(opts.privateKey, "missing private key")

			conn.publicKey = component.data.deserializeKey(opts.publicKey, "ec-public")
			conn.privateKey = component.data.deserializeKey(opts.privateKey, "ec-private")
		else
			conn.publicKey, conn.privateKey = component.data.generateKeyPair(256)
		end
	end

	local packet = string.char(0, opts.encryption)

	if opts.encryption == rcps.encryption.stdencrypt256 then
		packet = packet .. conn.publicKey.serialize()
	end

	rcp.writeAsync(dest, destPort, internalPort, packet)

	table.insert(_CONNS, conn)

	return conn
end

---@type rcps.vtable
rcps.nothingTable = {
	connected = function (sesh, encryption) end,
	disconnected = function (sesh, exitCode, msg) end,
	sent = function (sesh, data)
		return true, ""
	end,
	responded = function (sesh, packetID, accepted, response) end,
	timeout = function (sesh, packetID) end,
}

---@param dest atomnet.address
---@param destPort integer
---@param vtable rcps.vtable
---@param timeout number
---@param opts? rcps.connectOpts
---@return rcps.session?
function rcps.connectSync(dest, destPort, vtable, timeout, opts)
	local conn = rcps.connect(dest, destPort, vtable, opts)
	local deadline = computer.uptime() + timeout
	while true do
		local now = computer.uptime()
		if now >= deadline then
			rcps.disconnect(conn, rcps.exit.timeout, "", true)
			return
		end
		-- wait for SOMETHING to happen
		local ev = event.pull(deadline - now)
		if ev == "interrupted" then
			error("interrupted", 2)
		end
		if conn.state ~= "connecting" then break end
	end
	if conn.state == "closed" then return nil end
	return conn
end

---@param conn rcps.session
---@param code rcps.exit
---@param msg string
---@param requested? boolean
function rcps.disconnect(conn, code, msg, requested)
	if conn.state == "closed" then return end
	conn.state = "closed"
	for i=#_CONNS, 1, -1 do
		if _CONNS[i] == conn then
			table.remove(_CONNS, i)
			break
		end
	end
	conn.vtable.disconnected(conn, code, msg)
	if not requested then
		-- send it out!!!
		local packet = string.char(1, code) .. msg
		packet = encryptMessage(conn, packet)
		rcp.writeAsync(conn.src, conn.srcPort, conn.port, packet)
	end
end

---@param conn rcps.session
---@param data string
---@return string
function rcps.sendAsync(conn, data)
	local packet = string.char(2) .. data
	packet = encryptMessage(conn, packet)
	return rcp.writeAsync(conn.src, conn.srcPort, conn.port, packet)
end

---@param conn rcps.session
---@param data string
---@param timeout? number
---@return boolean, string?
function rcps.send(conn, data, timeout)
	local packet = string.char(2) .. data
	packet = encryptMessage(conn, packet)
	local ok, msg = rcp.write(conn.src, conn.srcPort, conn.port, packet, timeout)
	if msg then msg = decryptMessage(conn, msg, true) end
	if msg == "" then msg = nil end
	return ok, msg
end

return rcps
