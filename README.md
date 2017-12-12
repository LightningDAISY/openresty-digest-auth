# NAME
Openresty-digest-auth

# INSTALL
lua-resty-memcached is required

```
sudo luarocks install lua-resty-memcached
```

modify nginx.conf

```
    location /members {
        access_by_lua_file /path/2/digest.lua;
    }
```

restart the openresty-process
```
sudo systemctl restart openresty.service
```

# CONFIGURE

```
vim digest.lua
```

set your memcached's hostname, port
```
local memcachedConfig = {
	hostname = "127.0.0.1", -- meybe cannot resolve "localhost"
	port = 11211,
	expireSec = 10 * 60, -- 10 minute
}
```

set your digest-auth accounts
```
-- user = plain-password
local Users = {
	abc = "def",
}
```


