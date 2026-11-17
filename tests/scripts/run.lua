-- Script tests for checks/*.lua and checks/lib/*.lua with a mock `p`. Run with the interpreter the router uses:
--   luajit tests/scripts/run.lua      or      lua5.3 tests/scripts/run.lua
-- from the repository root. No network, no zprobe.
package.path = "checks/lib/?.lua;" .. package.path

local failed, total = 0, 0
local function eq(got, want, what)
  total = total + 1
  if got ~= want then
    failed = failed + 1
    print(("FAIL %s: got %s, want %s"):format(what, tostring(got), tostring(want)))
  end
end

-- ---- json ----
local json = require "json"
local v = assert(json.decode('{"a":[1,2.5,"x\\u00e9\\ud83d\\ude00\\n"],"b":{"c":true,"d":null},"e":-3e2}'))
eq(#v.a, 3, "json array length"); eq(v.a[2], 2.5, "json float"); eq(v.a[3], "x\xc3\xa9\xf0\x9f\x98\x80\n", "json unicode escapes")
eq(v.b.c, true, "json true"); eq(v.b.d, nil, "json null leaves the key out"); eq(v.e, -300, "json exponent")
eq(select(2, json.decode('{"a":')) ~= nil, true, "json truncated is an error")
eq(select(2, json.decode('[1,2] x')) ~= nil, true, "json trailing data is an error")
eq(json.decode('[null]')[1], json.null, "json null in an array")
eq(json.encode({ b = 1, a = { 1, 2, "x\"y" } }), '{"a":[1,2,"x\\"y"],"b":1}', "json encode")
eq(json.encode({}), "{}", "json empty table")
eq(json.decode(json.encode({ s = "tab\t\1" })).s, "tab\t\1", "json control characters round trip")
local deep = string.rep("[", 100) .. string.rep("]", 100)
eq(json.decode(deep), nil, "json depth limit")

-- ---- url ----
local url = require "url"
local u = url.parse("https://User@Video.Example.com:8443/a/b?x=1&y=2#frag")
eq(u.host, "video.example.com", "url host"); eq(u.port, 8443, "url port"); eq(u.path, "/a/b?x=1&y=2", "url path"); eq(u.query, "x=1&y=2", "url query")
eq(url.parse("https://example.com").path, "/", "url empty path")
eq(url.parse("not a url"), nil, "url no scheme")
eq(url.resolve("https://a.example/x/y?q=1", "/z"), "https://a.example/z", "resolve absolute path")
eq(url.resolve("https://a.example/x/y", "z"), "https://a.example/x/z", "resolve relative")
eq(url.resolve("https://a.example/x/y", "//b.example/q"), "https://b.example/q", "resolve scheme-relative")
eq(url.resolve("https://a.example/x", "http://c.example/"), "http://c.example/", "resolve absolute")
eq(url.registrable("rr1---sn-abc.googlevideo.com"), "googlevideo.com", "registrable")
eq(url.registrable("www.example.co.uk"), "example.co.uk", "registrable two-level suffix")
eq(url.same_site("www.speedtest.net", "speedtest.net"), true, "same site www")
eq(url.same_site("a.example.com", "blocked.isp.example"), false, "other site")
eq(url.unescape_json("https:\\/\\/rr1.googlevideo.com\\/x?a=1\\u0026b=2"), "https://rr1.googlevideo.com/x?a=1&b=2", "unescape_json")
eq(url.percent_decode("a%20b+c"), "a b c", "percent decode"); eq(url.percent_encode("a b/c"), "a%20b%2Fc", "percent encode")

-- ---- generic.lua, with a mock p ----
local generic = dofile("checks/generic.lua")
local function mock(replies)
  local p, calls, out = {}, {}, {}
  for _, k in ipairs { "tls", "quic", "http", "fetch" } do
    p[k] = function(self, a) calls[#calls + 1] = { k, a }; return table.remove(replies, 1) end
  end
  function p:ok(d) out.v, out.d = "ok", d; return out end
  function p:fail(c, d) out.v, out.c, out.d = "fail", c, d; return out end
  return p, calls, out
end
local function run(args, replies)
  args.min_bytes = args.min_bytes or 65536; args.path = args.path or "/"; args.host = args.host or "example.com"
  local p, calls, out = mock(replies)
  generic.check(p, args)
  return out, calls
end

local o = run({ proto = "tls", stage = "screen" }, { { class = "ok", detail = "server_hello" } })
eq(o.v, "ok", "screen ok"); eq(o.d, "server_hello", "screen detail")
o = run({ proto = "tls", stage = "screen" }, { { class = "rst", detail = "eof" } })
eq(o.v, "fail", "screen rst"); eq(o.c, "rst", "screen rst class")
o = run({ proto = "quic", stage = "confirm" }, { { class = "timeout", detail = "no_reply" } })
eq(o.c, "timeout", "quic timeout")
o = run({ proto = "tls", stage = "confirm" }, { { class = "ok", status = 200, bytes = 70000, headers = {} } })
eq(o.v, "ok", "download ok"); eq(o.d, "bytes_70000", "download detail")
o = run({ proto = "tls", stage = "confirm" }, { { class = "stalled", detail = "stall_18000", bytes = 18000, headers = {} } })
eq(o.c, "stalled", "freeze is a failure"); eq(o.d, "stall_18000", "freeze detail")
o = run({ proto = "tls", stage = "confirm" }, { { class = "ok", status = 200, bytes = 5000, headers = {} } })
eq(o.d, "complete_5000", "short complete 2xx")
o = run({ proto = "tls", stage = "confirm" }, { { class = "ok", status = 403, bytes = 900, headers = {} } })
eq(o.v, "ok", "error page still means reachable"); eq(o.d, "status_403", "error page detail")
o = run({ proto = "tls", stage = "confirm" }, { { class = "ok", status = 451, bytes = 900, headers = {} } })
eq(o.c, "forged", "451")
-- the SpeedTest case: a short redirect is not a page
o = run({ proto = "tls", stage = "confirm", host = "www.speedtest.net" },
        { { class = "ok", status = 302, bytes = 300, headers = { location = "https://blocked.isp.example/" } } })
eq(o.c, "forged", "foreign redirect"); eq(o.d, "redirect_foreign", "foreign redirect detail")
local o2, calls = run({ proto = "tls", stage = "confirm", host = "speedtest.net", ip = "1.2.3.4", port = 8443 },
        { { class = "ok", status = 301, bytes = 200, headers = { location = "https://www.speedtest.net/x" } },
          { class = "ok", status = 200, bytes = 90000, headers = {} } })
eq(o2.v, "ok", "same-site redirect followed"); eq(#calls, 2, "two fetches")
eq(calls[2][2].host, "www.speedtest.net", "second fetch host"); eq(calls[2][2].path, "/x", "second fetch path")
eq(calls[2][2].ip, nil, "ip is not carried to another name")
o2, calls = run({ proto = "tls", stage = "confirm", host = "a.example", ip = "1.2.3.4" },
        { { class = "ok", status = 302, bytes = 0, headers = { location = "/next" } },
          { class = "ok", status = 200, bytes = 90000, headers = {} } })
eq(calls[2][2].ip, "1.2.3.4", "ip is kept for the same name"); eq(calls[2][2].path, "/next", "relative redirect")
o = run({ proto = "tls", stage = "confirm" },
        { { class = "ok", status = 302, bytes = 0, headers = { location = "/a" } },
          { class = "ok", status = 302, bytes = 0, headers = { location = "/b" } } })
eq(o.c, "forged", "second redirect"); eq(o.d, "redirect_twice", "second redirect detail")
o = run({ proto = "tls", stage = "confirm" }, { { class = "ok", status = 302, bytes = 0, headers = {} } })
eq(o.d, "redirect_no_location", "redirect without Location")
o = run({ proto = "tls", stage = "confirm" },
        { { class = "ok", status = 302, bytes = 0, headers = { location = "http://example.com/" } } })
eq(o.v, "ok", "same-site redirect to plain http is not a block")

print(("scripts: %d/%d passed (%s)"):format(total - failed, total, _VERSION .. (jit and " " .. jit.version or "")))
os.exit(failed == 0 and 0 or 1)
