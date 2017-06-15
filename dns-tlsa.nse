description = [[
Ateemps to get more information from a server by requesting the server nsid[1],
and asking for id.server[2] and version.bind. This script dose the same as the
following two dig commands:
  - dig CH TXT bind.version @target
  - dig +nsid CH TXT id.server @target

[1]http://www.ietf.org/rfc/rfc5001.txt
[2]http://www.ietf.org/rfc/rfc4892.txt
]]

---
-- @usage
-- nmap -sSU -p 53 --script dns-nsid <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-nsid: 
-- |   NSID dns.example.com (646E732E6578616D706C652E636F6D)
-- |   id.server: dns.example.com
-- |_  bind.version: 9.7.3-P3
---

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "default"}

require "stdnse"
require "shortport"
require "dns"

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)	
	local result = {}
	local domain = "nohats.ca."
	local status, resp = dns.query("_443._tcp." .. domain, {host = host.ip, dtype='TLSA', retAll=true, retPkt=true })
	if ( status ) then
		if ( status ) then
		end
	end
end
