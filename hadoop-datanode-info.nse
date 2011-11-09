description = [[
Scrapes the datanode status page.  

information gathered:
 * Log Directory (reletive to the http://host:port/)

For more information about hadoop, see:
 * http://hadoop.apache.org/
 * http://en.wikipedia.org/wiki/Apache_Hadoop
]]

---
---
-- @args hadoop-info.force force this script to on http(s) ports
-- this arg applies to all hadoop-*-info scripts
--
-- @usage
-- nmap -sV --script hadoop-datanode-info.nse -p 50075 host
--
-- @output
-- PORT      STATE SERVICE         REASON
-- 50075/tcp open  hadoop-datanode syn-ack
-- | hadoop-datanode-info: 
-- |_  Logs: /logs/
---


author = "john.r.bond@gmail.com"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}

require ("shortport")
require ("http")

portrule = function(host, port)
        local force = stdnse.get_script_args('hadoop-info.force')
        if not force then
                return shortport.http and port.number ~= 80  and port.number ~= 443
        else
                return true
        end
end

action = function( host, port )

        local result = {}
	local uri = "/browseDirectory.jsp"
	stdnse.print_debug(1, ("%s:HTTP GET %s:%s%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, uri))
	local response = http.get( host.targetname or host.ip, port.number, uri )
	stdnse.print_debug(1, ("%s: Status %s"):format(SCRIPT_NAME,response['status-line'] or "No Response"))  
	if response['status-line'] and response['status-line']:match("200%s+OK") and response['body']  then
		port.version.name = "hadoop-datanode"
        	port.version.product = "Apache Hadoop"
		nmap.set_port_version(host, port, "hardmatched")
		local body = response['body']:gsub("%%","%%%%")
		stdnse.print_debug(2, ("%s: Body %s\n"):format(SCRIPT_NAME,body))  
		 if body:match("([^][\"]+)\">Log") then
                        local logs = body:match("([^][\"]+)\">Log")
                        stdnse.print_debug(1, ("%s: Logs %s"):format(SCRIPT_NAME,logs))  
                        table.insert(result, ("Logs: %s"):format(logs))
                end
		return stdnse.format_output(true, result)
	end
end
