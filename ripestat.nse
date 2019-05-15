description = [[
]]

---
-- @usage
-- @args ripestat.verbose (default = false) also fetch geoip and reverse dns information for each prefix
-- nmap  --script ripestat <target>
--
-- @output
--Host script results:
--| ripestat: 
--|   ASN: 3333
--|   Owner: RIPE-NCC-AS - Reseaux IP Europeens Network Coordination Centre (RIPE NCC)
--|   Transit ASN(s): 
--|     AS286 (KPN - KPN Internet Backbone)
--|     .....
--|     AS25074 (INETBONE-AS - MESH GmbH)
--|   Provids Transit to ASN(s): 
--|     ASN: 2121
--|     Owner: RIPE-MEETING-AS - Reseaux IP Europeens Network Coordination Centre (RIPE NCC)
--|   Prefix: 193.0.18.0/23
--|     GeoIP: NL,(2011-03-15T00:00:00,2011-04-15T00:00:00,2011-05-15T00:00:00,2011-06-15T00:00:00,2011-07-15T00:00:00,2011-08-15T00:00:00,2011-09-15T00:00:00,2011-10-15T00:00:00,2011-11-15T00:00:00,2011-12-15T00:00:00,2012-01-15T00:00:00)
--|     rDNS domain:18.0.193.in-addr.arpa
--|       Description: RIPE NCC Internal Use
--|       Name Servers: pri.authdns.ripe.net,sns-pb.isc.org,sec1.apnic.net,sec3.apnic.net,ns3.nic.fr,tinnie.arin.net
--|     rDNS domain:19.0.193.in-addr.arpa
--|       Description: RIPE NCC Internal Use
--|       Name Servers: pri.authdns.ripe.net,sns-pb.isc.org,sec1.apnic.net,sec3.apnic.net,ns3.nic.fr,tinnie.arin.net
--|   .....
--|   Prefix: 2001:67c:2e8::/48
--|     GeoIP: NL,(2012-03-15T00:00:00)
--|     GeoIP: EU,(2011-03-15T00:00:00,2011-04-15T00:00:00,2011-05-15T00:00:00,2011-06-15T00:00:00,2011-07-15T00:00:00,2011-08-15T00:00:00,2011-09-15T00:00:00,2011-10-15T00:00:00,2011-11-15T00:00:00,2011-12-15T00:00:00,2012-01-15T00:00:00,2012-02-15T00:00:00)
--|     rDNS domain:8.e.2.0.c.7.6.0.1.0.0.2.ip6.arpa
--|       Description: RIPE-NCC Infrastructure
--|__     Name Servers: pri.authdns.ripe.net,sns-pb.isc.org,sec1.apnic.net,sec3.apnic.net,ns3.nic.fr,tinnie.arin.net
---

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "default"}

local stdnse = require "stdnse"
local shortport = require "shortport"
local json = require "json"
local http = require "http"
local target = require "target"

local httphost = "stat.ripe.net"
local apiuri = "/plugin/"
local format = "/data.json"

hostrule = function()
        return true
end

getJson = function(plugin, resource)
	local url = apiuri .. plugin .. format .. "?resource=" .. resource
	local response = http.get(httphost, 443, url)
	if ( 200 ~= response.status ) then
	    stdnse.debug(1,"FAIL HTTP: %s", response.status)
		return false
	end
	local status, parsed = json.parse(response.body)
	 if ( not(status) ) then
                return false, "Failed to parse response from server"
        end
	return parsed
end
	
getGeolocHistory = function(prefix)
	local parsed = getJson("geoloc-history",prefix)
	local results = {}
	if not(parsed) then
		return parsed
	end
	for _, i in ipairs(parsed.data.months) do
		local dist = i.distributions
		if #dist > 0 then
			local key = dist[1].country .. "," .. dist[1].city
			if ( not (results[key]) ) then
				results[key]  = i.month
			else
				results[key] =  results[key] .. "," .. i.month
				
			end
			stdnse.debug(2,"%s: %s",key,  results[key])
		end
	end
	return results
end

getReverseDNS = function(prefix)
	local parsed = getJson("reverse-dns",prefix)
	local results = {}
	if not(parsed) then
		return parsed
	end
	if #parsed.messages > 0 then 
		return false
	end
		
	if #parsed.data.delegations > 0 then
		for _, delegation in ipairs(parsed.data.delegations) do
			local entry = {}
			entry.domain = ""
			entry.description = ""
			entry.nserver = {}
			for _, attr in  ipairs(delegation) do
				stdnse.debug(4,"name/value: %s/%s", attr.key,attr.value)
				if attr.key == "domain" then
					entry.domain = attr.value
					stdnse.debug(3,"domain: %s", entry.domain)
				elseif attr.key == "descr" then
					entry.description = attr.value
					stdnse.debug(3,"description: %s", entry.description)
				elseif attr.key == "nserver" then
					table.insert(entry.nserver,attr.value)
					stdnse.debug(3,"name server: %s", attr.value)
					if target.ALLOW_NEW_TARGETS then
						stdnse.debug("Added targets: "..attr.value)
						local status,err = target.add(attr.value)
					end
				end
			end
			table.insert(results,entry)
		end
	end
	return results

end

getAnnouncedPrefixes = function(asn)
	local parsed = getJson("announced-prefixes",asn)
	local prefixes = {}
	if not(parsed) then
		return parsed
	end
	for _,prefix in ipairs(parsed.data.prefixes) do
		table.insert(prefixes,prefix.prefix)
		stdnse.debug(1,"Prefix: %s", prefix.prefix)
		nmap.registry.ripestat_prefixs[prefix.prefix] = asn 
	end
	return prefixes
end

getAsnNeighbours = function(asn)
	local parsed = getJson("asn-neighbours",asn)
	local left, right = {}, {}
	if not(parsed) then
		return parsed
	end
	stdnse.debug(2,"Count L/R: %s/%s",parsed.data.neighbour_counts.left,parsed.data.neighbour_counts.right)
	for _,neighbour in ipairs(parsed.data.neighbours) do
		stdnse.debug(2,"AS: %s (%s)",neighbour.asn, neighbour.type)
		if neighbour.type == "left" then
			table.insert(left,neighbour.asn)
		elseif neighbour.type == "right" then
			table.insert(right,neighbour.asn)
		end
	end
	stdnse.debug(1,"Neighbour Left: %s",table.concat(left,","))
	stdnse.debug(1,"Neighbour Right: %s",table.concat(right,","))
	return left,right
end

getAsOverview = function(asn)
	local parsed = getJson("as-overview",asn)
	if not(parsed) then
		return parsed
	end
	stdnse.debug(1,"Owner: %s",parsed.data.holder)
	return parsed.data.holder
end

getNetworkInfo = function(ip)
	local parsed = getJson("network-info",ip)
	if not(parsed) then
		return parsed
	end
	stdnse.debug(1,"ASNS: %s",table.concat(parsed.data.asns,(',')))
	stdnse.debug(1,"Prefix: %s",parsed.data.prefix)
	return parsed.data.asns, parsed.data.prefix
end

getPrefixOverview = function(prefix)
	local parsed = getJson("prefix-overview",prefix)
	if not(parsed) then
		return parsed
	end
	stdnse.debug(2, "Block: %s", parsed.data.block.resource)
	stdnse.debug(2, "owner: %s", parsed.data.block.name)
	return parsed.data.block.resource, parsed.data.block.name
end
quadToInt = function (ip)
        local addr = stdnse.strsplit("%.",ip)
        return (tonumber(addr[1])*16777216 + tonumber(addr[2])*65536 
                        + tonumber(addr[3])*256 + tonumber(addr[4]))    
end
ipInPrefix = function(ip, prefix)
	local network, subnet = stdnse.strsplit("/", prefix)
	local network_int, ip_int = quadToInt(network), quadToInt(ip)
	local end_address = network_int + math.pow(2,(32-subnet)) - 1
	if ip >= network_int and ip <= end_address then
		stdnse.pritn_debug(1,"already scaned prefix")
		return true
	end
	return false
end

action = function(host, port)	
	local result, lookup, prefixes = {}, {}, {}
	local info = {}
	local verbose = stdnse.get_script_args('ripestat.verbose')
	if not verbose then 
		verbose = false 
	end

	info.asns, info.prefixes, info.leftNeighbours, info.rightNeighbours  = {}, {}, {}, {}
    info.prefix = {}
	nmap.registry.ripestat_asns, nmap.registry.ripestat_prefixs = {}, {}
	if #nmap.registry.ripestat_prefixs > 0 then
		for _,prefix in ipairs(nmap.registry.ripestat_prefixs) do
			if ipInPrefix(host.ip,prefix) then
				info.asns = nmap.registry.ripestat_prefixs[prefix]
			end 
		end
	else
		info.asns, info.prefix = getNetworkInfo(host.ip)
		nmap.registry.ripestat_prefixs[info.prefix] = info.asns
		for prefix,asns in pairs(nmap.registry.ripestat_prefixs) do
			stdnse.debug("HERE: " .. prefix .. " : " .. table.concat(asns, ','))
		end
	end
    for _, asn in ipairs(info.asns) do
      if nmap.registry.ripestat_asns[asn] then
          return "ASN (" .. asn .. ") Already scanned" 
      else
          nmap.registry.ripestat_asns[asn] = true
      end
    end

    -- seriously lua arrays start at 1 wtf!
    -- # TODO: support multiple ASN's better
	info.owner = getAsOverview(info.asns[1])
	info.leftNeighbours.list, info.rightNeighbours.list = getAsnNeighbours(info.asns[1])
	local prefixes_tmp = getAnnouncedPrefixes(info.asns[1])

	table.sort(info.leftNeighbours.list)
	table.sort(info.rightNeighbours.list)

	table.insert(result,"ASN: " .. info.asns[1] .. "(" .. info.owner .. ")")
	if #info.leftNeighbours.list > 0 then
		if verbose then
			info.leftNeighbours.owner = {}
			table.insert(result,"Transit ASN(s): ")
			for _,neighbour in ipairs(info.leftNeighbours.list) do
				info.leftNeighbours.owner[neighbour] = getAsOverview(neighbour)
				if  info.leftNeighbours.owner[neighbour] then
					table.insert(result,{"AS" .. neighbour .. " (" .. info.leftNeighbours.owner[neighbour].. ")"})
				else
					table.insert(result,{"ASN: " .. neighbour})
				end
			end
		else
			table.insert(result,"Transit ASN(s): " .. table.concat(info.leftNeighbours.list,","))
		end
	end
	if #info.rightNeighbours.list > 0 then
		if verbose then
			info.rightNeighbours.owner = {}
			table.insert(result,"Provids Transit to ASN(s): " )
			for _,neighbour in ipairs(info.rightNeighbours.list) do
				info.rightNeighbours.owner[neighbour] = getAsOverview(neighbour)
				if info.rightNeighbours.owner[neighbour] then
					table.insert(result,{"AS" .. neighbour .. " (" .. info.rightNeighbours.owner[neighbour].. ")"})
				else
					table.insert(result,{"ASN: " .. neighbour})
				end
			end
		else
			table.insert(result,"Provids Transit to ASN(s): " .. table.concat(info.rightNeighbours.list,","))
		end
	end
	table.insert(prefixes_tmp,info.prefix)

        for _, pre_tmp in ipairs(prefixes_tmp) do lookup[pre_tmp] = true end	
	for i in pairs (lookup) do table.insert(info.prefixes,i) end
	table.sort(info.prefixes)
	info.block = {}

	for _, pre in ipairs(info.prefixes) do
		table.insert(result, "Prefix: " .. pre)
		if target.ALLOW_NEW_TARGETS then
			stdnse.debug("Added targets: "..pre)
			local status,err = target.add(pre)
		end
		if verbose then
			info.prefixes[pre] = {}
			stdnse.debug(1,"Working with: %s", pre)
			info.prefixes[pre].block, info.prefixes[pre].name = getPrefixOverview(pre)
			stdnse.debug("%s : %s",  info.prefixes[pre].block,  info.prefixes[pre].name )
--			if not (info.block[info.prefixes[pre].block]) then
--		stdnse.debug("HRHRHRHRHR")
--			 	info.block[info.prefixes[pre].block] = {}
--			 	info.block[info.prefixes[pre].block].name = info.prefixes[pre].name 
--			 	info.block[info.prefixes[pre].block].prefixes = {} 
--			 	info.block[info.prefixes[pre].block].domains = getReverseDNS(info.prefixes[pre].block)
--			 	info.block[info.prefixes[pre].block].location = getGeolocHistory(info.prefixes[pre].block)
--			end
			info.prefixes[pre].location = getGeolocHistory(pre)
			info.prefixes[pre].domains = getReverseDNS(pre)
			table.insert(result,{"Block: " .. info.prefixes[pre].block .. " (" .. info.prefixes[pre].name .. ")"})
			
			if info.prefixes[pre].location  then 
				for country, dates in pairs(info.prefixes[pre].location) do
			 		table.insert(result, {"GeoIP: " .. country .. "(" .. dates .. ")"})
			 	end
			end
			if info.prefixes[pre].domains  then 
			 	for _, domain in ipairs(info.prefixes[pre].domains) do
			 		table.insert(result, { "rDNS domain:" .. domain.domain} )
			 		table.insert(result, {{"Description: " .. domain.description}})
			 		table.insert(result, {{"Name Servers: " .. table.concat(domain.nserver,",")}})
			 	end
			end
		end
	end
--	stdnse.debug("%s",#info.block)
--	for block in pairs(info.block) do
--		table.insert(result,{"Block: " .. block.prefixes .. " (" .. block.name .. ")"})
--		if block.location then
--			for country, dates in pairs(block.location) do
--		 		table.insert(result, {"GeoIP: " .. country .. "(" .. dates .. ")"})
--		 	end
----		end
--		if block.domains  then 
--		 	for _, domain in ipairs(block.domains) do
--		 		table.insert(result, { "rDNS domain:" .. domain.domain} )
--		 		table.insert(result, {{"Description: " .. domain.description}})
--		 		table.insert(result, {{"Name Servers: " .. table.concat(domain.nserver,",")}})
--		 	end
--		end
--		
--	end
	
	return stdnse.format_output(true, result)
end
