-- JSON for check scripts. Pure Lua, the common subset of 5.1 and 5.3 (no bit operators, no //).
--   json.decode(text) -> value | nil, error     null in an object leaves the key out; in an array it is json.null
--   json.encode(value) -> text                  tables with 1..n keys are arrays, others objects (keys sorted)
local M = {}

M.null = setmetatable({}, { __tostring = function() return "null" end })

local sbyte, sfind, ssub, schar, sformat = string.byte, string.find, string.sub, string.char, string.format
local floor, concat = math.floor, table.concat

local function utf8char(cp)
  if cp < 0x80 then return schar(cp) end
  if cp < 0x800 then return schar(0xC0 + floor(cp / 64), 0x80 + cp % 64) end
  if cp < 0x10000 then
    return schar(0xE0 + floor(cp / 4096), 0x80 + floor(cp / 64) % 64, 0x80 + cp % 64)
  end
  return schar(0xF0 + floor(cp / 262144), 0x80 + floor(cp / 4096) % 64, 0x80 + floor(cp / 64) % 64, 0x80 + cp % 64)
end
M.utf8char = utf8char

local escapes = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', b = '\b', f = '\f', n = '\n', r = '\r', t = '\t' }

local function skip(s, i) return sfind(s, "[^ \t\r\n]", i) or #s + 1 end

local function dstring(s, i)
  local parts, n, j = {}, 0, i + 1
  while true do
    local a = sfind(s, '["\\]', j)
    if not a then error("unterminated string", 0) end
    if a > j then n = n + 1; parts[n] = ssub(s, j, a - 1) end
    if sbyte(s, a) == 34 then return concat(parts), a + 1 end
    local c = ssub(s, a + 1, a + 1)
    if c == "u" then
      local hex = ssub(s, a + 2, a + 5)
      if not hex:find("^%x%x%x%x$") then error("bad \\u escape", 0) end
      local cp, nxt = tonumber(hex, 16), a + 6
      if cp >= 0xD800 and cp < 0xDC00 then
        local lo = s:match("^\\u(%x%x%x%x)", nxt)
        lo = lo and tonumber(lo, 16)
        if lo and lo >= 0xDC00 and lo < 0xE000 then
          cp = 0x10000 + (cp - 0xD800) * 1024 + (lo - 0xDC00)
          nxt = nxt + 6
        end
      end
      n = n + 1; parts[n] = utf8char(cp)
      j = nxt
    else
      local r = escapes[c]
      if not r then error("bad escape", 0) end
      n = n + 1; parts[n] = r
      j = a + 2
    end
  end
end

local dvalue
function dvalue(s, i, depth)
  if depth > 64 then error("too deep", 0) end
  i = skip(s, i)
  local c = sbyte(s, i)
  if c == 34 then return dstring(s, i) end
  if c == 123 then
    local obj = {}
    i = skip(s, i + 1)
    if sbyte(s, i) == 125 then return obj, i + 1 end
    while true do
      i = skip(s, i)
      if sbyte(s, i) ~= 34 then error("object key expected at " .. i, 0) end
      local k
      k, i = dstring(s, i)
      i = skip(s, i)
      if sbyte(s, i) ~= 58 then error("':' expected at " .. i, 0) end
      local v
      v, i = dvalue(s, i + 1, depth + 1)
      if v ~= M.null then obj[k] = v end
      i = skip(s, i)
      local d = sbyte(s, i)
      if d == 44 then i = i + 1
      elseif d == 125 then return obj, i + 1
      else error("',' or '}' expected at " .. i, 0) end
    end
  end
  if c == 91 then
    local arr, n = {}, 0
    i = skip(s, i + 1)
    if sbyte(s, i) == 93 then return arr, i + 1 end
    while true do
      local v
      v, i = dvalue(s, i, depth + 1)
      n = n + 1; arr[n] = v
      i = skip(s, i)
      local d = sbyte(s, i)
      if d == 44 then i = i + 1
      elseif d == 93 then return arr, i + 1
      else error("',' or ']' expected at " .. i, 0) end
    end
  end
  if ssub(s, i, i + 3) == "true" then return true, i + 4 end
  if ssub(s, i, i + 4) == "false" then return false, i + 5 end
  if ssub(s, i, i + 3) == "null" then return M.null, i + 4 end
  local a, b = sfind(s, "^-?%d+%.?%d*[eE]?[+-]?%d*", i)
  if a then return tonumber(ssub(s, a, b)), b + 1 end
  error("unexpected character at " .. i, 0)
end

function M.decode(s)
  if type(s) ~= "string" then return nil, "not a string" end
  local ok, v, i = pcall(dvalue, s, 1, 0)
  if not ok then return nil, v end
  if v == M.null then v = nil end
  i = skip(s, i)
  if i <= #s then return nil, "trailing data at " .. i end
  return v
end

local enc_esc = { ['"'] = '\\"', ['\\'] = '\\\\', ['\b'] = '\\b', ['\f'] = '\\f', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }

local function estring(s)
  return '"' .. s:gsub('[%c"\\]', function(c) return enc_esc[c] or sformat("\\u%04x", sbyte(c)) end) .. '"'
end

local function evalue(v, out, depth)
  local t = type(v)
  if t == "string" then out[#out + 1] = estring(v)
  elseif t == "number" then
    if v ~= v or v == math.huge or v == -math.huge then out[#out + 1] = "null"
    elseif v == floor(v) and v > -1e15 and v < 1e15 then out[#out + 1] = sformat("%d", v)
    else out[#out + 1] = sformat("%.14g", v) end
  elseif t == "boolean" then out[#out + 1] = v and "true" or "false"
  elseif t == "table" then
    if v == M.null then out[#out + 1] = "null"; return end
    if depth > 64 then error("too deep", 0) end
    local n = #v
    local count = 0
    for _ in pairs(v) do count = count + 1 end
    if n > 0 and count == n then
      out[#out + 1] = "["
      for i = 1, n do
        if i > 1 then out[#out + 1] = "," end
        evalue(v[i], out, depth + 1)
      end
      out[#out + 1] = "]"
    else
      local keys = {}
      for k in pairs(v) do if type(k) == "string" then keys[#keys + 1] = k end end
      table.sort(keys)
      out[#out + 1] = "{"
      for i, k in ipairs(keys) do
        if i > 1 then out[#out + 1] = "," end
        out[#out + 1] = estring(k) .. ":"
        evalue(v[k], out, depth + 1)
      end
      out[#out + 1] = "}"
    end
  else out[#out + 1] = "null" end
end

function M.encode(v)
  local out = {}
  evalue(v, out, 0)
  return concat(out)
end

return M
