-- URL helpers for check scripts. Pure Lua.
local M = {}

-- "https://host:8443/a/b?x=1#f" -> { scheme, host, port, path ("/a/b?x=1"), query }
function M.parse(u)
  local scheme, rest = u:match("^(%a[%w+.-]*)://(.*)$")
  if not scheme then return nil end
  local auth, path = rest:match("^([^/?#]*)(.*)$")
  path = path:gsub("#.*$", "")
  local host, port = auth:match("^[^@]*@?(.-):(%d+)$")
  if not host then host = auth:gsub("^[^@]*@", "") end
  if path == "" then path = "/" elseif path:sub(1, 1) == "?" then path = "/" .. path end
  return { scheme = scheme:lower(), host = host:lower(), port = port and tonumber(port) or nil,
           path = path, query = path:match("%?(.*)$") }
end

-- the absolute URL a Location header means when received for `base`
function M.resolve(base, loc)
  if loc:find("^%a[%w+.-]*://") then return loc end
  local b = M.parse(base)
  if not b then return nil end
  local origin = b.scheme .. "://" .. b.host .. (b.port and (":" .. b.port) or "")
  if loc:sub(1, 2) == "//" then return b.scheme .. ":" .. loc end
  if loc:sub(1, 1) == "/" then return origin .. loc end
  if loc:sub(1, 1) == "?" then return origin .. (b.path:gsub("%?.*$", "")) .. loc end
  local dir = b.path:gsub("%?.*$", ""):gsub("[^/]*$", "")
  return origin .. dir .. loc
end

local second_level = { co = true, com = true, org = true, net = true, gov = true, edu = true, ac = true, ne = true, ["or"] = true, go = true }

-- the name a site is registered under: example.com for a.b.example.com, example.co.uk for www.example.co.uk
function M.registrable(host)
  local labels = {}
  for l in host:lower():gmatch("[^.]+") do labels[#labels + 1] = l end
  local n = #labels
  if n <= 2 then return table.concat(labels, ".") end
  local keep = (#labels[n] == 2 and second_level[labels[n - 1]]) and 3 or 2
  return table.concat(labels, ".", n - keep + 1, n)
end

function M.same_site(a, b) return M.registrable(a) == M.registrable(b) end

function M.percent_decode(s)
  return (s:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

function M.percent_encode(s)
  return (s:gsub("[^%w%-_.~]", function(c) return string.format("%%%02X", c:byte()) end))
end

-- text taken out of a JSON string literal in a page, without the quotes: https:\/\/a.example\/x?a=1&b=2
function M.unescape_json(s)
  local json = require "json"
  return (s:gsub("\\(u%x%x%x%x)", function(u) return json.utf8char(tonumber(u:sub(2), 16)) end)
            :gsub("\\(.)", function(c) return c == "n" and "\n" or c == "t" and "\t" or c end))
end

return M
