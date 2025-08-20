-- AtomNET Web Protocol, the AtomNET equivalent to HTTP
-- It is on port 80, using RCPS for transmission
-- A lot of status codes and details are based off of HTTP 1.1

--[[

// WIP

]]

local event = require("event")
local atomnet = require("atomnet")
local rcps = require("atomnet.rcps")

local awp = {}

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
	partial = 206,
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

awp.port = 80

---@alias awp.headers table<string, string>

return awp
