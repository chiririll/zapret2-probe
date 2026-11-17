-- Embedded in zprobe (see Makefile). Runs inside the sandbox, before a check script's own code.
-- Called as normalize(decl, protos, raw): turns the arguments of a job into what the script declared.
-- Returns the table, or nil and an error code that becomes the result detail.
local reserved = { proto = true, stage = true, prepared = true }

return function(decl, protos, raw)
  decl = decl or {}
  raw = raw or {}
  local out = {}
  for k in pairs(raw) do
    if not decl[k] and not reserved[k] then return nil, "bad_arg_" .. tostring(k) end
  end
  for k, d in pairs(decl) do
    local ty = d.type or "string"
    local v = raw[k]
    if v == nil then
      v = d.default
      if v == nil and d.required then return nil, "missing_arg_" .. k end
    end
    if v ~= nil then
      if ty == "number" then
        v = tonumber(v)
        if v == nil then return nil, "bad_arg_" .. k end
      elseif ty == "bool" then
        if v == "true" or v == "1" or v == 1 then v = true
        elseif v == "false" or v == "0" or v == 0 then v = false
        elseif type(v) ~= "boolean" then return nil, "bad_arg_" .. k end
      elseif ty == "list" then
        if type(v) == "string" then
          local t = {}
          for item in v:gmatch("[^,]+") do t[#t + 1] = item end
          v = t
        elseif type(v) ~= "table" then
          return nil, "bad_arg_" .. k
        end
      else
        if type(v) == "number" or type(v) == "boolean" then v = tostring(v)
        elseif type(v) ~= "string" then return nil, "bad_arg_" .. k end
      end
    end
    out[k] = v
  end
  out.prepared = raw.prepared
  out.stage = raw.stage or "confirm"
  out.proto = raw.proto or (protos and protos[1]) or "tls"
  if type(out.stage) ~= "string" then return nil, "bad_arg_stage" end
  if protos and #protos > 0 then
    local found = false
    for _, p in ipairs(protos) do if p == out.proto then found = true end end
    if not found then return nil, "bad_proto_" .. tostring(out.proto) end
  end
  return out
end
