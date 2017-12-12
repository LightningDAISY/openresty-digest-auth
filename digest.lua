#! /usr/bin/env lua
local realm = "members"
local logFilename = "/var/www/aimi/error.log"
local nonceLength = 52
local memcachedConfig = {
	hostname = "127.0.0.1", -- meybe cannot resolve "localhost"
	port = 11211,
	expireSec = 10 * 60, -- 10 minute
}

-- user = plain-password
local Users = {
	abc = "def",
}

local function response401()
	return [[
<!DOCTYPE html>
<html>
	<head>
		<title>401 Unauthorized</title>
	</head>
	<body>
		<h1>Unauthorized</h1>
		<p>
			This server could not verify that you are authorized to access the document requested. Either you supplied the wrong credentials (e.g., bad password), or your browser doesn't understand how to supply the credentials required.
		</p>
	</body>
<html>
	]]
end

local function writeLog(str)
	local fp = assert(io.open (logFilename, 'a'))
	fp:write(str .. "\n")
	fp:close()
end

local function memcachedConnect()
	if not memcachedConfig then return end
	local hostname = memcachedConfig.hostname
	if not hostname then return end
	local port = memcachedConfig.port or 6379
	local schema = memcachedConfig.authSchema

	local RestyMemcache = require 'resty.memcached'
	local kvs, err = RestyMemcache:new()
	kvs:set_timeout(1000)
	local ok,err,errcode,sqlstate = kvs:connect(hostname, port)
	if not ok then
		writeLog("ConnectionError: " .. err)
		return false
	end
	return kvs
end

local function md5(str)
	if type(str) == 'number' then str = tostring(str) end
	return ngx.md5(str)
end

local function createRandomNonce(columnSize)
	local rand = ""
	local seed = os.time() .. collectgarbage('count')
	local str  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ=_"
	rand = ''
	for i=1,columnSize do
		math.randomseed(os.time() .. collectgarbage('count') .. i)
		local idx = tostring(math.random(1, 39))
		rand = rand .. str:sub(idx,idx)
	end

	-- memcache begin
	local kvs = memcachedConnect()
	if kvs then
		local ok, err = kvs:set(rand, 1, memcachedConfig.expireSec)
		if not ok then
			self:writeLog("Memcached error : " .. err)
			return
		end
	end
	-- memcache end
	return rand
end

local function parseAuthorization()
	local result = {}
	local authorization = ngx.req.get_headers()["Authorization"];
	if not authorization then return end
	authorization = authorization:gsub("^Digest%s+", "")
	for st in authorization:gmatch("[^,]+") do
		st = st:gsub("^%s", "")
		st = st:gsub("%s$", "")
		local key,value = st:match('([^=]+)="?([^"]+)"?')
		result[key] = value
	end
	return result
end

local function valid(auth)
	for i,key in ipairs({"username", "realm", "nonce", "cnonce", "qop" }) do
		if not auth[key] then return false end
	end
	return true
end

local function createPasswordHash(username)
	local password = Users[username]
	if not password then return false end
	return md5(
		string.format(
			"%s:%s:%s",
			username,
			realm,
			password
		)
	)
end

local function nonceIsExists(nonce)
	local kvs = memcachedConnect()
	if not kvs then return true end
	local res, flags, err = kvs:get(nonce)
	if err then
		writeLog("Memcached error : " .. err)
		return
	end
	if res then return true end
end

--
-- return (bool)isSuccess, (int)errorType
--
local function authenticate()
	local auth = parseAuthorization()
	if not valid(auth) then return false,false end
	local a1 = createPasswordHash(auth.username)
	if not a1 then return false,false end
	local a2 = md5(
		string.format(
			"%s:%s",
			ngx.req.get_method(),
			ngx.var.request_uri
		)
	)
	local response = md5(
		string.format(
			"%s:%s:%s:%s:%s:%s",
			a1,
			auth.nonce,
			auth.nc,
			auth.cnonce,
			auth.qop,
			a2
		)
	)
	if auth.response == response then
		if nonceIsExists(auth.nonce) then return true,false	end
		return false,1
	end
	return false,false
end

local function showDigestAuth(state)
	local nonce = createRandomNonce(nonceLength)
	local digest = 'Digest realm="%s", nonce="%s", algorithm="MD5", qop="auth"'
	if state and state == 1 then
		digest = digest .. ", stale=true"
	end
	ngx.status = 401
	ngx.header.content_type = "text/html; charset=utf-8"
	ngx.header["WWW-Authenticate"] = string.format(
		digest,
		realm,
		nonce
	)
	ngx.say(response401())
	ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function main()
	local returnCode, state
	if ngx.req.get_headers()["Authorization"] then
		returnCode, state = authenticate()
		if returnCode then return true end
	end
	showDigestAuth(state)
end

main()

