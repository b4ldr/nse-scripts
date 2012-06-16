local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
]]

---
-- @usage
-- nmap --script flume-master-info -p 50070 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 50070/tcp open  flume-master syn-ack
-- | flume-master-info:
-- |   Started:  Wed May 11 22:33:44 PDT 2011
-- |   Version:  0.20.2-cdh3u1, f415ef415ef415ef415ef415ef415ef415ef415e
-- |   Compiled:  Wed May 11 22:33:44 PDT 2011 by bob from unknown
-- |   Upgrades:  There are no upgrades in progress.
-- |   Filesystem: /nn_browsedfscontent.jsp
-- |   Logs: /logs/
-- |   Storage:
-- |   Total       Used (DFS)      Used (Non DFS)  Remaining
-- |   100 TB      85 TB           500 GB          14.5 TB
-- |   Datanodes (Live):
-- |     Datanode: datanode1.example.com:50075
-- |     Datanode: datanode2.example.com:50075
---


author = "John R. Bond (john.r.bond@gmail.com)"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}


portrule = function(host, port)
	-- Run for the special port number, or for any HTTP-like service that is
	-- not on a usual HTTP port.
	return shortport.port_or_service ({35871}, "flume-master")(host, port)
		or (shortport.service(shortport.LIKELY_HTTP_SERVICES)(host, port) and not shortport.portnumber(shortport.LIKELY_HTTP_PORTS)(host, port))
end

-- ref: http://lua-users.org/wiki/TableUtils
function table_count(tt, item)
	local count
	count = 0
	for ii,xx in pairs(tt) do
		if item == xx then count = count + 1 end
	end
	return count
end

getenv = function( host, port )
	local result = {}
	local intresting_keys = {"java.runtime","java.version","java.vm.name","java.vm.vendor","java.vm.version","os","user.name","user.country","user.language,user.timezone"}
	local uri = "/masterenv.jsp"
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response" ))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		for name,value in string.gmatch(body,"<tr><th>([^][<]+)</th><td><div%sclass=[^][>]+>([^][<]+)") do
			stdnse.print_debug(1, ("%s:  %s=%s "):format(SCRIPT_NAME,name,value:gsub("^%s*(.-)%s*$", "%1")))
			if nmap.verbosity() > 1 then
				 result[#result+1] = ("%s: %s"):format(name,value:gsub("^%s*(.-)%s*$", "%1"))
			else
				for i,v in ipairs(intresting_keys) do
					if name:match(("^%s"):format(v)) then
						result[#result+1] = ("%s: %s"):format(name,value:gsub("^%s*(.-)%s*$", "%1"))
					end
				end
			end
		end
	end
	return result
end
action = function( host, port )

	local result = {}
	local uri = "/flumemaster.jsp"
	local nodes = {  }
	local zookeepers = {  }
	local hbasemasters = {  }
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		local capacity = {}
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		port.version.name = "flume-master"
		port.version.product = "Apache Flume"
		if body:match("Version:%s*</b>([^][,]+)") then
			local version = body:match("Version:%s*</b>([^][,]+)")
			stdnse.print_debug(1, ("%s: Version %s"):format(SCRIPT_NAME,version))
			result[#result+1] =  ("Version: %s"):format(version)
			port.version.version = version
		end
		if body:match("Compiled:%s*</b>([^][<]+)") then
			local compiled = body:match("Compiled:%s*</b>([^][<]+)")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			result[#result+1] =  ("Compiled: %s"):format(compiled)
		end
		if body:match("ServerID:%s*([^][<]+)") then
			local upgrades = body:match("ServerID:%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: ServerID %s"):format(SCRIPT_NAME,upgrades))
			result[#result] = ("ServerID: %s"):format(upgrades)
		end
		table.insert(result, "Flume nodes:")
		for logical,physical,hostname in string.gmatch(body,"<tr><td>([%w%.-_:]+)</td><td>([%w%.]+)</td><td>([%w%.]+)</td>") do
			stdnse.print_debug(2, ("%s:  %s (%s) %s"):format(SCRIPT_NAME,physical,logical,hostname))
			if (table_count(nodes, hostname) == 0) then
				nodes[#nodes+1] = hostname
			end
		end
		if next(nodes) ~= nil then 
			result[#result+1] = nodes
		end
		result[#result+1] = "Zookeeper Master:"
		for zookeeper in string.gmatch(body,"Dhbase.zookeeper.quorum=([^][\"]+)") do
			if (table_count(zookeepers, zookeeper) == 0) then
				zookeepers[#zookeepers+1] = zookeeper
			end
		end
		if next(zookeepers) ~= nil then 
			result[#result+1] = zookeepers
		end
		result[#result+1] = "Hbase Master Master:"
		for hbasemaster in string.gmatch(body,"Dhbase.rootdir=([^][\"]+)") do
			if (table_count(hbasemasters, hbasemaster) == 0) then
				hbasemasters[#hbasemasters+1] = hbasemaster
			end
		end
		if next(hbasemasters) ~= nil then 
			result[#result+1] = hbasemasters
		end
		result[#result+1] = "Enviroment: "
		result[#result+1] = getenv(host, port)
		return stdnse.format_output(true, result)
	end
end
