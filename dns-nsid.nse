description = [[
Enumerates DNS names using the DNSSEC NSEC-walking technique.

Output is arranged by domain. Within a domain, subzones are shown with
increased indentation.

The NSEC response record in DNSSEC is used to give negative answers to
queries, but it has the side effect of allowing getNSIDeration of all
names, much like a zone transfer. This script doesn't work against
servers that use NSEC3 rather than NSEC.
]]

---
-- @args dns-nsec-enum.domains The domain or list of domains to
-- getNSIDerate. If not provided, the script will make a guess based on the
-- name of the target.
--
-- @usage
-- nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=example.com <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-nsec-enum:
-- |   example.com
-- |     bulbasaur.example.com
-- |     charmander.example.com
-- |     dugtrio.example.com
-- |     www.dugtrio.example.com
-- |     gyarados.example.com
-- |       johto.example.com
-- |       blue.johto.example.com
-- |       green.johto.example.com
-- |       ns.johto.example.com
-- |       red.johto.example.com
-- |     ns.example.com
-- |     snorlax.example.com
-- |_    vulpix.example.com

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
        local result = {}
        for _, rec in ipairs(pktRR) do
               	if rec[label] then
			if rec.dtype == 41 then
		 		stdnse.print_debug("number %d", string.len(rec.data))
				local _,nsid =  bin.unpack(">H".. ( string.len(rec.data) - 3 ), rec.data , 4)
		 		stdnse.print_debug("hex %s", nsid)
		 		stdnse.print_debug("asci %s", hextoasci(nsid))

			else
		 		stdnse.print_debug(rec.data)
                        	result[#result + 1] = rec[label]
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
		local id_server = rr_filter(result.answers,'TXT')
		local nsid = rr_filter(result.add,'OPT')
		 -- stdnse.print_debug(id_server.dname)
			
	end

end

action = function(host, port)
	local result = getNSID(host, port)
	-- return stdnse.format_output(true, output)
end
