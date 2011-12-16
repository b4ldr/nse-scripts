description = [[
Ateemps to get more information from a server by requesting the server nsid[1], and asking 
for id.server[2] and version.bind.  This script dose the same as the following two dig commands
dig CH TXT bind.version @target
dig +nsid CH TXT id.server @target

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
local function hextoasci(str)
	return string.gsub(str, '[0-9a-fA-F][0-9a-fA-F]', function(m) return string.char(loadstring('return 0x' .. m)()) end)
end

local function rr_filter(pktRR, label)
        local result = ""
        for _, rec in ipairs(pktRR) do
               	if rec[label] then
			if rec.dtype == 41 then
				if #rec.data > 0 then
					local _,nsid =  bin.unpack(">H".. ( string.len(rec.data) - 3 ), rec.data , 4)
                        		result =  hextoasci(nsid) .. " (" ..  nsid ..")"
				else 
					result = "No Answer"
				end
			else
                        	result = rec.data
                	end
		end
        end
        return result
end

-- Enumerate a single domain.
local function getNSID(host, port)

	local result = {}
	local status, result, nsec
	stdnse.print_debug("Trying id.server")
	status, result = dns.query("id.server", {host = host.ip, dtype='TXT', class=3, retAll=true, retPkt=true, nsid=true, dnssec=true})
	if status then
		local nsid = rr_filter(result.add,'OPT')
		result[#result + 1] = "NSID: " .. nsid
		local id_server = rr_filter(result.answers,'TXT')
		result[#result + 1] = "id.server: " .. id_server
			
	end
	status, bind_version = dns.query("version.bind", {host = host.ip, dtype='TXT', class=3})
	if status then
		result[#result + 1] = "bind.version: " .. bind_version
	end
	return result
end

action = function(host, port)
	local output = getNSID(host, port)
	return stdnse.format_output(true, output)
end
