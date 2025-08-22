-- AtomNET Web Protocol, the AtomNET equivalent to HTTP
-- It is on port 80, using OSP for transmission
-- A lot of status codes and details are based off of HTTP 1.1

--[[

// big endian

struct awp_header {
    char name[]; // NULL-terminated
    char body[]; // NULL-terminated
};

struct awp_request {
    char header[] = "AWP\0";
    uint8_t majorVersion;
    uint8_t minorVersion;
    uint32_t bodySize;
    char method[]; // See awp.methods
    char resourcePath[]; // NULL-terminated
    awp_header headers[]; // terminated by header with an empty name and body
    uint8_t body[bodySize];
};

struct awp_response {
    uint16_t responseCode;
    uint32_t bodySize;
    awp_header headers[]; // terminated by header with an empty name and body
    uint8_t body[bodySize];
};

]]

local event = require("event")
local atomnet = require("atomnet")
local osp = require("atomnet.osp")
local component = require("component")
local computer = require("computer")

local awp = {}

awp.prefix = "AWP\0"

---@enum awp.method
awp.methods = {
	get = "GET",
	post = "POST",
	delete = "DELETE",
	head = "HEAD",
	put = "PUT",
	patch = "PATCH",
}

---@enum awp.statusCode
awp.statusCodes = {
	-- ok stuff
	switchProtocols = 101,
	processing = 102,
	-- good stuff
	success = 200,
	created = 201,
	accepted = 202,
	mirrored = 203,
	noContent = 204,
	partial = 206,
	list = 207,
	-- meh stuff
	redirect = 301,
	seeOther = 303,
	-- bad stuff
	badRequest = 400,
	needsAuth = 401,
	paymentRequired = 402,
	forbidden = 403,
	notFound = 404,
	badMethod = 405,
	timeout = 408,
	conflict = 409,
	gone = 410,
	teapot = 418,
	locked = 423,
	tooEarly = 425, -- bad replay
	switchRequired = 426,
	rateLimited = 429,
	tooBig = 431, -- way too big
	illegal = 451, -- nasty censorship
	-- turbo bad
	internalServerError = 500,
	badGateway = 502,
	unavailable = 503,
	gatewayTimeout = 504,
	badVersion = 505,
	outOfSpace = 507,
}

---@enum awp.contentType
awp.contentTypes = {
	text = "text/plain",
	csv = "text/csv",
	lua = "text/lua",
	shell = "text/sh", -- not application/x-sh!! that's dumb!!!
	json = "text/json",
	lon = "text/lon",
	other = "application/stream",
	mtar = "application/mtar",
}

awp.standardHeaders = {
	--- Compression used
	compression = "Compression",
	--- Compression methods accepted in A;B;C... format. If absent, assume no compression is supported
	compressionAccepted = "Compression-Accepted",
	--- Authentication code
	authentication = "Authentication",
	--- For proxies, the address or host this was forwarded for
	forwardedFor = "Forwarded-For",
	--- The host
	host = "Host",
	--- The content type desired (for requests) or used (for responses)
	type = "Content-Type",
	--- The user agent, or client, used.
	agent = "User-Agent",
	--- Range would be A-B, where A and B are units of data. They must be numbers followed by an optional unit, K for 1024 bytes, M for 1024 K, G for 1024 M.
	--- the response should return that range. When compression is used, it should return the compressed version of that range, not the range of the compressed
	--- data.
	range = "Range",
	--- An identifier of the server software, similar to agent
	server = "Server",
	--- The cookie, a set of key value pairs in the form K=V;K2=V2;...etc. If it is in requests, it is the cookie used. If it is in responses, the client
	--- should set the cookie data to the specified value.
	cookie = "Cookie",
	--- The amount, in seconds, that the data has been in cache for
	age = "Age",
}

---@enum awp.compression
awp.compression = {
	deflate = "deflate",
}

---@param compression awp.compression
---@param dataSize integer
function awp.compressionSupported(compression, dataSize)
	if compression == awp.compression.deflate then
		if not component.isAvailable("data") then return false end
		if component.data.getLimit() < dataSize then return false end
		return component.data.deflate ~= nil -- should never be the case, tier 1 supports it
	end
	return false
end

---@param compression awp.compression
---@param data string
---@return string
function awp.compress(compression, data)
	if compression == awp.compression.deflate then
		return assert(component.data.deflate(data))
	end
	return ""
end

---@param compression awp.compression
---@param data string
---@return string
function awp.decompress(compression, data)
	if compression == awp.compression.deflate then
		return assert(component.data.inflate(data))
	end
	return ""
end

awp.port = 80

awp.majorVersion = 0
awp.minorVersion = 0

awp.defaultServer = "REF-AWP-SERVER" -- Reference AWP
awp.defaultAgent = "REF-AWP-CLIENT" -- Reference AWP

---@alias awp.headers table<string, string>

---@alias awp.handler fun(method: string, path: string, headers: awp.headers, data: string): awp.statusCode, awp.headers, string

---@class awp.serverConfig
---@field keys? rcps.serverKeys
---@field handler awp.handler
---@field logger? fun(msg: string)
---@field requestMaximumTime number
---@field timeoutPerPacket number
---@field server string
---@field host string
---@field port? integer

---@class awp.serverSideRequest
---@field server awp.server
---@field expiration number
---@field timeout number
---@field stream osp.stream
---@field state "prefix"|"method"|"path"|"headers"|"body"|"done"
---@field majorVersion integer
---@field minorVersion integer
---@field method string
---@field resourcePath string
---@field headers awp.headers
---@field bodySize integer
---@field lastPacketCount integer

---@class awp.server
---@field config awp.serverConfig
---@field port integer
---@field requests awp.serverSideRequest[]
local server = {}
server.__index = server

---@param config awp.serverConfig
function awp.serve(config)
	---@type awp.serverSideRequest[]
	local requests = {}

	---@type awp.server
	local s

	local port = config.port or awp.port
	port = osp.open(port, function(stream)
		s:log("New connection")

		---@type awp.serverSideRequest
		local req = {
			server = s,
			expiration = computer.uptime() + config.requestMaximumTime,
			timeout = computer.uptime() + config.timeoutPerPacket,
			bodySize = 0,
			headers = {},
			majorVersion = 0,
			minorVersion = 0,
			method = "",
			resourcePath = "",
			state = "prefix",
			stream = stream,
			lastPacketCount = 0,
		}

		table.insert(requests, req)
	end, config.keys)

	s = setmetatable({
		config = config,
		port = port,
		requests = requests,
	}, server)
	return s
end

---@param fmt string
function server:log(fmt, ...)
	local msg = string.format(fmt, ...)
	if self.config.logger then
		self.config.logger(msg)
	end
end

---@param request awp.serverSideRequest
---@param status awp.statusCode
---@param headers awp.headers
---@param body string
function server:respond(request, status, headers, body)
	local function f()
		-- super buffered
		local buf = ""
		buf = buf .. string.pack(">I2>I4", status, #body)
		for name, val in pairs(headers) do
			buf = buf .. name .. "\0" .. val .. "\0"
		end

		buf = buf .. "\0\0"
		request.stream:writeAsync(buf .. body)
		-- we're done here
		request.state = "done"
	end

	local ok, err = pcall(f) -- sometimes race conditions cause errors if we send something while a nasty evil connection is being closed
	if not ok then
		self:log("error during response: %s", err)
	end
end

---@param request awp.serverSideRequest
function server:processRequest(request)
	-- if bro disconnected before we sent them a response, fuck that guy
	if request.stream:isDisconnected() then
		request.state = "done"
		return
	end
	-- we're already responding to it
	if request.stream:writesPending() then
		return
	end

	local now = computer.uptime()

	if request.stream.packetCount > request.lastPacketCount then
		request.lastPacketCount = request.stream.packetCount
		request.timeout = now + request.server.config.timeoutPerPacket
	end

	if now >= request.expiration or now >= request.timeout then
		self:respond(request, awp.statusCodes.badRequest, {
			[awp.standardHeaders.server] = request.server.config.server,
			[awp.standardHeaders.host] = request.server.config.host,
		}, "timeout")
		request.state = "done"
		self:log("Request timed out")
		return
	end

	if request.state == "prefix" then
		if request.stream:getBufferSize() >= 10 then
			if request.stream:read(4) ~= awp.prefix then
				self:log("missing header")
				self:respond(request, awp.statusCodes.badRequest, {
					[awp.standardHeaders.server] = request.server.config.server,
					[awp.standardHeaders.host] = request.server.config.host,
				}, "missing header")
				request.state = "done"
				return
			end
			local major = request.stream:read(1):byte(1, 1)
			local minor = request.stream:read(1):byte(1, 1)
			if major > awp.majorVersion or minor > awp.minorVersion then
				self:log("unsupported request")
				self:respond(request, awp.statusCodes.badRequest, {
					[awp.standardHeaders.server] = request.server.config.server,
					[awp.standardHeaders.host] = request.server.config.host,
				}, "outdated")
				request.state = "done"
				return
			end
			request.majorVersion = major
			request.minorVersion = minor
			request.bodySize = string.unpack(">I4", request.stream:read(4) or "")
			request.state = "method"
			self:log("%d byte request with AWP %d.%d", request.bodySize, request.majorVersion, request.minorVersion)
		end
	end

	if request.state == "method" then
		if request.stream:bufferHas("\0") then
			request.method = assert(request.stream:readCString())
			request.state = "path"
			self:log("method %s", request.method)
		end
	end

	if request.state == "path" then
		if request.stream:bufferHas("\0") then
			request.resourcePath = assert(request.stream:readCString())
			request.state = "headers"
			self:log("path %s", request.resourcePath)
		end
	end

	if request.state == "headers" then
		while request.stream:bufferHas("\0", 2) do
			local name = assert(request.stream:readCString())
			local val = assert(request.stream:readCString())

			if name == "" and val == "" then
				request.state = "body"
				self:log("End of headers")
				break
			end
			request.headers[name] = val
			self:log("Header: %s = %s", name, val)
		end
	end

	if request.state == "body" then
		if request.stream:getBufferSize() >= request.bodySize then
			local body = request.stream:read(request.bodySize) or ""
			self:log("Body: %s", atomnet.formatSize(#body))
			local ok, code, headers, resp = pcall(self.config.handler, request.method, request.resourcePath, request.headers, body)
			if not ok then
				local err = code
				---@cast err string Trust me bro I know what I'm doing
				resp = err
				code = awp.statusCodes.internalServerError
				headers = {}
			end
			self:log("Response: %d %s", code, atomnet.formatSize(#resp))

			request.state = "done"
			self:respond(request, code, headers, resp)
		end
	end
end

---@param request awp.serverSideRequest
function server:isRequestOver(request)
	return request.state == "done" and (not request.stream:writesPending())
end

function server:process()
	for _, req in ipairs(self.requests) do
		self:processRequest(req)
	end

	for i=#self.requests, 1, -1 do
		if self:isRequestOver(self.requests[i]) then
			self.requests[i].stream:close()
			table.remove(self.requests, i)
		end
	end
end

---@param interval? number
--- Loops until an interrupted event is queued
--- An interval above 0 but below infinity is recommended in order
--- to prevent attacks based off spamming slow connections
function server:loop(interval)
	interval = interval or 0.05
	while true do
		local e = event.pull(interval)
		self:process()
		if e == "interrupted" then break end
	end
end

function server:close()
	for _, req in ipairs(self.requests) do
		req.stream:close()
	end
	osp.close(self.port)
end

---@class awp.connectOpts
---@field rcps? rcps.connectOpts
---@field noDefaultHeaders? boolean
---@field noAutoCompression? boolean
---@field connectTimeout? number
---@field secure? boolean

---@param method awp.method
---@param uri string
---@param body string
---@param headers? awp.headers
---@param opts? awp.connectOpts
---@return osp.stream?
function awp.requestConnection(method, uri, body, headers, opts)
	opts = opts or {}

	local hostStr = uri
	local path = "/"
	do
		local i = string.find(uri, "/", nil, true)
		if i then
			hostStr = string.sub(uri, 1, i-1)
			path = string.sub(uri, i)
		end
	end
	local port = awp.port
	do
		local i = string.find(hostStr, ":", nil, true)
		if i then
			local portStr = string.sub(hostStr, i+1)
			hostStr = string.sub(hostStr, 1, i-1)
			port = math.floor(assert(tonumber(portStr), "invalid URI"))
		end
	end

	---@type awp.headers
	local h = {}

	if headers then
		for name, val in pairs(headers) do h[name] = val end
	end

	if not opts.noDefaultHeaders then
		if not h[awp.standardHeaders.agent] then
			h[awp.standardHeaders.agent] = awp.defaultAgent
		end

		---@type awp.compression[]
		local compressions = {
			awp.compression.deflate,
		}

		if not h[awp.standardHeaders.compressionAccepted] then
			---@type awp.compression[]
			local supported = {}

			for _, c in ipairs(supported) do
				if awp.compressionSupported(c, #body) then
					table.insert(supported, c)
				end
			end

			if #supported > 0 then
				h[awp.standardHeaders.compressionAccepted] = table.concat(supported, ';')
			end
		end

		if (not h[awp.standardHeaders.compression]) and (not opts.noAutoCompression) then
			--- Assumes server supports the compression even if we might not
			--- This is, ofc, questionable.
			---@type string?
			local comp
			for _, c in ipairs(compressions) do
				if awp.compressionSupported(c, #body) then
					comp = c
				end
			end

			if comp then
				h[awp.standardHeaders.compression] = comp
				body = awp.compress(comp, body)
			end
		end
	end

	local addr = atomnet.resolveHostSync(hostStr)

	local conn = osp.connectSync(addr, port, opts.connectTimeout, opts.rcps)
	if not conn then
		return
	end

	local buf = ""

	buf = buf .. awp.prefix .. string.char(awp.majorVersion, awp.minorVersion) .. string.pack(">I4", #body)
	buf = buf .. method .. "\0" .. path .. "\0"
	for name, val in pairs(h) do
		buf = buf .. name .. "\0" .. val .. "\0"
	end
	buf = buf .. "\0\0"
	conn:write(buf .. body)
	return conn
end

---@param method awp.method
---@param uri string
---@param body string
---@param headers? awp.headers
---@param opts? awp.connectOpts
---@return awp.statusCode, string, awp.headers
function awp.requestSync(method, uri, body, headers, opts)
	local conn = awp.requestConnection(method, uri, body, headers, opts)
	if not conn then
		error("connection failed", 2)
	end
	local respHeader = assert(conn:read(6), "missing response")

	local respCode, respBodySize = string.unpack(">I2>I4", respHeader)

	---@type awp.headers
	local respH = {}

	while true do
		local name = assert(conn:readCString(), "missing header name")
		local val = assert(conn:readCString(), "missing header value")
		if name == "" or val == "" then break end
		respH[name] = val
	end

	local respBody = assert(conn:read(respBodySize), "missing body")

	conn:close()

	return respCode, respBody, respH
end

---@class awp.download
---@field responseCode awp.statusCode
---@field bodySize integer
---@field headers awp.headers
---@field stream osp.stream
local download = {}
download.__index = download

---@param method awp.method
---@param uri string
---@param body string
---@param headers? awp.headers
---@param opts? awp.connectOpts
---@return awp.download?
function awp.download(method, uri, body, headers, opts)
	local stream = awp.requestConnection(method, uri, body, headers, opts)
	if not stream then return end
	local d = setmetatable({}, download)
	d.stream = stream
	local info = stream:read(6)
	if not info then
		stream:close()
		return
	end
	d.responseCode, d.bodySize = string.unpack(">I2>I4", info)
	d.headers = {}
	while true do
		local name = stream:readCString()
		local val = stream:readCString()

		if (not name) or (not val) then
			stream:close()
			return
		end

		if name == "" and val == "" then break end
		d.headers[name] = val
	end
	return d
end

function download:getBytesDownloaded()
	local n = self.stream:getBufferSize()
	for _, pending in ipairs(self.stream.pendingReadBuffer) do
		n = n + #pending.data
	end
	return n
end

function download:isDone()
	return self:getBytesDownloaded() == self.bodySize
end

---@return number
function download:getProgress()
	return self:getBytesDownloaded() / self.bodySize
end

return awp
