-- The default check: can this host be reached, and does a page load, over the given protocol?
--   tls   screen: a ServerHello. confirm: a download (fetch) of min_bytes, or a complete answer.
--         A redirect to the same registrable domain is followed once; anywhere else, or twice, it is forged.
--   quic  the server's Initial at both stages (zprobe has no HTTP/3, so a freeze over QUIC is not seen).
--   http  a status line that is not a forged answer.
local url = require "url"

local function verdict(p, r)
  if r.class == "ok" then return p:ok(r.detail) end
  return p:fail(r.class, r.detail)
end

return {
  title = "Reachability",
  protos = { "tls", "quic", "http" },
  args = {
    host = { required = true, help = "name to connect to" },
    ip = { help = "connect here instead of resolving host (for tests and hand runs)" },
    port = { type = "number", help = "TCP/UDP port, default by protocol" },
    path = { default = "/", help = "request path" },
    min_bytes = { type = "number", default = 65536, help = "bytes a download has to deliver (tls, confirm)" },
  },
  check = function(p, args)
    local at = { host = args.host, ip = args.ip, port = args.port }
    if args.proto == "quic" then return verdict(p, p:quic(at)) end
    if args.proto == "http" then at.path = args.path; return verdict(p, p:http(at)) end
    if args.stage == "screen" then return verdict(p, p:tls(at)) end

    local host, path = args.host, args.path
    for hop = 0, 1 do
      local r = p:fetch{ host = host, ip = at.ip, port = at.port, path = path, min_bytes = args.min_bytes, max_body = 0 }
      if r.class ~= "ok" then return p:fail(r.class, r.detail) end
      local st = r.status or 0
      if st == 451 then return p:fail("forged", "http_451") end
      if st >= 300 and st < 400 then
        local loc = r.headers.location
        if not loc then return p:fail("forged", "redirect_no_location") end
        local target = url.parse(url.resolve("https://" .. host .. path, loc) or "")
        if not target or not url.same_site(host, target.host) then return p:fail("forged", "redirect_foreign") end
        if target.scheme ~= "https" then return p:ok("redirect_" .. st) end
        if hop == 1 then return p:fail("forged", "redirect_twice") end
        if target.host ~= host then at = {} end       -- another name: resolve it
        host, path = target.host, target.path
      else
        if r.bytes >= args.min_bytes then return p:ok("bytes_" .. r.bytes) end
        if st >= 200 and st < 300 then return p:ok("complete_" .. r.bytes) end
        return p:ok("status_" .. st)        -- the host answered with an error page: reachable, as before
      end
    end
    return p:fail("forged", "redirect_twice")
  end,
}
