description = [[
Implements the edns-client-subnet IETF draft[1].  Can be used to find what ip
address CDN networks provide when serving different client ip/subnet.  not sure
who has implmented this yet other then google.
[1]http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-00
]]

---
-- @args dns-client-subnet.domain The domain to lookup
-- @args dns-client-subnet.address the client address to use
-- @args dns-client-subnet.nameserver nameserver to use.  (default = host.ip)
-- 
-- @usage
-- nmap -sU -p 53 --script dns-client-subnet i --script-args \
-- dns-client-subnet.domain=www.example.com,dns-client-subnet.address=192.168.0.1 \
-- [,dns-client-subnet.nameserver=8.8.8.8] <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-client-subnet: 
-- |_  A : 127.0.0.1,127.0.0.2,127.0.0.3
---

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery" }

require "stdnse"
require "shortport"
require "dns"

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})


local function rr_filter(pktRR, label)
	for _, rec in ipairs(pktRR, label) do
		if ( rec[label] and 0 < #rec.data ) then
			if ( dns.types.OPT == rec.dtype ) then
				local ip = {}
				local pos, _, len, family, src_mask, scope_mask  = bin.unpack(">SSSCC", rec.data)
				pos,  ip[1], ip[2], ip[3], ip[4] =  bin.unpack(">C4", rec.data, pos)
				address = table.concat(ip, ".")
				stdnse.print_debug("family: %s",family)
				stdnse.print_debug("src_mask: %s",src_mask)
				stdnse.print_debug("scope_mask: %s",scope_mask)
				stdnse.print_debug("address: %s",address)
				if ( len ~= #rec.data - pos + 1 ) then
					return false, "Failed to decode client-subnet"
				end
			end
		end
	end
end

action = function(host, port)	
	local result = {}
	local nameserver = stdnse.get_script_args('dns-client-subnet.nameserver')
	local domain =  stdnse.get_script_args('dns-client-subnet.domain')
	local address =  stdnse.get_script_args('dns-client-subnet.address')
	local client_subnet = {}
	if not domain then
		return string.format("dns-client-subnet.domain missing")
	end
	if not address then
		return string.format("dns-client-subnet.address missing")
	end
	if not nameserver then
		nameserver = host.ip
	end

	client_subnet.family = 1
	client_subnet.address = address
	client_subnet.mask = 23
	-- local status, resp = dns.query(domain, {host = nameserver,  retAll=true, retPkt=true, client_subnet=client_subnet})
	local status, resp = dns.query(domain, {host = nameserver,  retAll=true, retPkt=true, client_subnet=client_subnet})
	if ( status ) then
		local status, answer = dns.findNiceAnswer(dns.types.A, resp, true)
		if ( status ) then
			if type(answer) == "table" then
				table.insert(result, ("A : %s"):format(table.concat(answer,",")))
			else
				table.insert(result, ("A : %s"):format(answer))
			end
		end
		rr_filter(resp.add,'OPT')
	end
	return stdnse.format_output(true, result)
end
