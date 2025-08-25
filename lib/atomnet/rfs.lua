-- Remote File System, built on top of ordered streams via OSP on port 21.
-- Not secure by itself, assumes RCPS security.
-- Sessions are not necessarily per-connection, there can be
-- multiple connections, even at the same time, for the same session.
-- Sessions are identified via *tokens*, 128-bit strings. These IDs do not have to be coupled to any authentication data, and thus
-- if they are truly randomized, the only way to get the active session of another machine/user is brute-force.
-- Sessions should also be temporary.
--[[
// Big endian

struct rfs_newSession {
	uint16_t magic = 'NS';
	uint8_t authAlgorithm;
	char username[]; // Null terminated
	union {
		void nothing;
		// auth stuff
	};
};

enum rfs_authAlgorithm {
	RFS_AUTH_NOPASS = 0, // there is no password, user is not secured in any way, likely a guest account
};

struct rfs_errorResponse {
	uint16_t magic = 'ER';
	char message[]; // Null terminated
};

struct rfs_statFile {
	uint16_t magic = 'SF';
	uint128_t session;
	char path[]; // NULL-terminated
};

struct rfs_statFileResponse {
	uint64_t modifiedTime;
	uint32_t size;
	uint8_t flags;
};

enum rfs_statFileFlags {
	READABLE = 1,
	WRITABLE = 2,
	DIRECTORY = 4,
};

struct rfs_move {
	uint16_t magic = 'MV';
	uint128_t session;
	char from[]; // NULL-terminated
	char to[]; // NULL-terminated
};

struct rfs_copy {
	uint16_t magic = 'CP';
	uint128_t session;
	char from[]; // NULL-terminated
	char to[]; // NULL-terminated
};

struct rfs_touch {
	uint16_t magic = 'TF';
	uint128_t session;
	char path[]; // NULL-terminated
};

struct rfs_mkdir {
	uint16_t magic = 'TD';
	uint128_t session;
	char path[]; // NULL-terminated
};

struct rfs_downloadFile {
	uint16_t magic = 'DF';
	uint128_t session;
	char path[]; // NULL-terminated
	uint32_t off; // 0 for start of file
	uint32_t len; // 0 for entire file
};

struct rfs_downloadFileResponse {
	uint32_t fileSize;
	uint8_t data[fileSize];
};

struct rfs_uploadFile {
	uint16_t magic = 'UF';
	uint128_t session;
	char path[]; // NULL-terminated
	uint32_t fileSize;
	uint8_t data[fileSize];
};

struct rfs_listDir {
	uint16_t magic = 'LS';
	uint128_t session;
	char path[]; // NULL-terminated
};

struct rfs_listDirResponse {
	uint16_t count;
	char entries[count]; // each NULL-terminated, directories end with a /
};

struct rfs_whoami {
	uint16_t magic = 'MI';
	uint128_t session;
};

struct rfs_goodResponse {
	uint16_t magic = 'GR';
	union {
		uint128_t newSessionToken;
		rfs_statFileResponse statFile;
		rfs_downloadFileResponse downloadFile;
		rfs_listDirResponse listDir;
		char whoami[];
	};
};

]]

local atomnet = require("atomnet")
local osp = require("atomnet.osp")
local bit32 = require("bit32")

local rfs = {}

rfs.port = 21

rfs.statFlags = {
	readable = 1,
	writable = 2,
	directory = 4,
}

---@class rfs.session
---@field token string
---@field stream osp.stream
local session = {}
session.__index = session

---@param token string
---@param stream osp.stream
function rfs.newSession(token, stream)
	return setmetatable({
		token = token,
		stream = stream,
	}, session)
end

---@enum rfs.authAlgorithm
rfs.authAlgorithm = {
	NOPASS = 0,
}

---@class rfs.loginOpts
---@field auth rfs.authAlgorithm
---@field port? integer
---@field rcps? rcps.connectOpts
---@field timeout? number

---@param address atomnet.address
---@param token string
---@param opts? rfs.loginOpts
---@return rfs.session?
function rfs.withToken(address, token, opts)
	opts = opts or {auth = rfs.authAlgorithm.NOPASS}
	local stream = osp.connectSync(address, opts.port or rfs.port, opts.timeout, opts.rcps)
	if not stream then
		return
	end

	return rfs.newSession(token, stream)
end

--- Returns true if good and false and the error message if bad response
--- For a good response, it only reads the 2 byte magic, not the contents.
---@return boolean, string?
function session:parseResponse()
	local magic = self.stream:read(2)

	if magic == 'GR' then
		return true
	end
	if magic == 'ER' then
		local msg = self.stream:readCString()
		return false, msg
	end

	return false, "bad response header"
end

function session:assertResponse()
	assert(self:parseResponse())
end

---@param address atomnet.address
---@param user string
---@param opts? rfs.loginOpts
---@return rfs.session?, string?
function rfs.login(address, user, opts)
	opts = opts or {auth = rfs.authAlgorithm.NOPASS}
	local sesh = rfs.withToken(address, string.rep("1", 16), opts)
	if not sesh then return nil, "connection failed" end

	sesh.stream:write("NS" .. string.char(opts.auth) .. user .. string.char(0))

	local ok, err = sesh:parseResponse()
	if not ok then return nil, err end

	sesh.token = assert(sesh.stream:read(16), "bad response")

	return sesh
end

function session:isClosed()
	return self.stream:isClosed()
end

function session:isDisconnected()
	return self.stream:isDisconnected()
end

function session:disconnect()
	self.stream:disconnect()
end

function session:close()
	self.stream:close()
end

function session:whoami()
	self.stream:write("MI" .. self.token)
	self:assertResponse()
	return (assert(self.stream:readCString(), "bad response"))
end

---@param path string
---@param dataSize integer
function session:uploadFilePrefix(path, dataSize)
	self.stream:write("UF" .. self.token .. path .. string.char(0) .. string.pack(">I4", dataSize))
end

---@param path string
---@param data string
function session:uploadFile(path, data)
	self:uploadFilePrefix(path, #data)
	self.stream:write(data)
end

---@param path string
---@param off? integer
---@param len? integer
---@return integer
function session:downloadFilePrefix(path, off, len)
	off = off or 0
	len = len or 0
	if len == math.huge then len = 0 end

	self.stream:write("DF" .. self.token .. path .. string.char(0) .. string.pack(">I4>I4", off, len))

	self:assertResponse()

	local fileSizeStr = assert(self.stream:read(4), "bad response")
	return (string.unpack(">I4", fileSizeStr))
end

---@param path string
---@param off? integer
---@param len? integer
---@return string
function session:downloadFile(path, off, len)
	local size = self:downloadFilePrefix(path, off, len)
	return (assert(self.stream:read(size), "bad response"))
end

---@param path string
---@return integer
function session:listPrefix(path)
	self.stream:write("LS" .. self.token .. path .. string.char(0))
	self:assertResponse()
	local countStr = assert(self.stream:read(2), "bad response")
	local count = string.unpack(">I2", countStr)

	return count
end

---@param path string
---@return string[]
function session:list(path)
	self.stream:write("LS" .. self.token .. path .. string.char(0))
	self:assertResponse()
	local countStr = assert(self.stream:read(2), "bad response")
	local count = string.unpack(">I2", countStr)

	local entries = {}

	for _=1, count do
		local entry = self.stream:readCString()
		assert(entry, "bad response")
		table.insert(entries, entry)
	end

	return entries
end

return rfs
