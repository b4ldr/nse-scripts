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

get_datanodes = function( host, port, Status )
	local result = {}
	local uri = "flumemaster.jsp" .. Status
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host, port, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response" ))
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))
		for datanodetmp in string.gmatch(body, "[%w%.:-_]+/browseDirectory.jsp") do
			local datanode = datanodetmp:gsub("/browseDirectory.jsp","")
			stdnse.print_debug(1, ("%s: Datanode %s"):format(SCRIPT_NAME,datanode))
			table.insert(result, ("Datanode: %s"):format(datanode))
			if target.ALLOW_NEW_TARGETS then
				if datanode:match("([%w%.]+)") then
					local newtarget = datanode:match("([%w%.]+)")
					stdnse.print_debug(1, ("%s: Added target: %s"):format(SCRIPT_NAME, newtarget))
					local status,err = target.add(newtarget)
				end
			end
		end
	end
	return result
end

action = function( host, port )

	local result = {}
	local uri = "/flumemaster.jsp"
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
			local version = body:match("Version:%s*<td>([^][,]+)")
			stdnse.print_debug(1, ("%s: Version %s"):format(SCRIPT_NAME,version))
			table.insert(result, ("Version: %s"):format(version))
			port.version.version = version
		end
		if body:match("Compiled:%s*</b>([^][<]+)") then
			local compiled = body:match("Compiled:%s*</b>([^][<]+)")
			stdnse.print_debug(1, ("%s: Compiled %s"):format(SCRIPT_NAME,compiled))
			table.insert(result, ("Compiled: %s"):format(compiled))
		end
		if body:match("ServerID:%s*([^][<]+)") then
			local upgrades = body:match("ServerID:%s*([^][<]+)")
			stdnse.print_debug(1, ("%s: ServerID %s"):format(SCRIPT_NAME,upgrades))
			table.insert(result, ("ServerID: %s"):format(upgrades))
		end
	end
end
