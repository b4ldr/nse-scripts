description = [[
Produces a list of prefixes for a given ASN.  This service uses the
a whois server provided by shadow servers and you should only override 
these options if you know what your are doing

Output is given in CIDR notation
If the <code>newtargets</code> script argument is given, all discovered 
prefixes  will be added to the Nmap target list rather than just listed 
in the output. *Warning * this may add more targets then you expect.

As mentioned this script relies on services provide by shadowservers 
more information on the services used can be found here and thanks freed0
adimino and any one else at shadow servers

http://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP

]]

---
-- @args asn-to-prefix.asn The asn number to search
-- @args asn-to-prefix.whois_server whois server to use default is asn.shadowserver.org
-- @args asn-to-prefix.whois_port whois port to conect to default is 43
-- @args newtargets prefixes discovered will be added to the nmap scan
--
-- @usage
-- nmap --script asn-to-prefix --script-args asn-to-prefix.asn={65000,65001}[asn-to-prefix.whois_server=asn.shadowserver.org,asn-to-prefix.whois_port=43,newtargets]
--
-- @output
-- 53/udp open  domain  udp-response
-- | asn-to-prefix:
-- |_    127.0.0.0/8

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery"}

require "stdnse"
require "shortport"
require "target"

prerule = function()
	return true
end

action = function(host, port)
	local asns, whois_server, whois_port, err, status
	local results = {} 

	asns = stdnse.get_script_args('asn-to-prefix.asn')
	whois_server = stdnse.get_script_args('asn-to-prefix.whois_server')
	whois_port = stdnse.get_script_args('asn-to-prefix.whois_port')
	newtargets = stdnse.get_script_args('asn-to-prefix.newtargets')

	if not asns then
		return stdnse.format_output(true, "asn-to-prefix.asn is a mandatory parameter")
	end
	if not whois_server then
		whois_server = "asn.shadowserver.org"
	end
	if not whois_port then
		whois_port = 43
	end

	for _, asn in ipairs(asns) do
		local socket = nmap.new_socket()

		local prefixs = {}
		prefixs['name'] = asn

		status, err = socket:connect(whois_server, whois_port)
		if ( not(status) ) then	
			table.insert(prefixs, err)
		else
			status, err = socket:send("prefix " .. asn .. "\n")
			if ( not(status) ) then	
				table.insert(prefixs, err)
			else

				-- useing recived lines here and setting to an a msiive number
				-- because when i used reciv i only got the first line
				-- im sure ther is a better way to do this so let me know 
				while true do 
					local status, data = socket:receive_lines(1) 
					if ( not(status) ) then	
						table.insert(prefixs, err)
						break
					else
						for i, prefix in ipairs(stdnse.strsplit("\n",data)) do
							table.insert(prefixs,prefix)
							if target.ALLOW_NEW_TARGETS then
								stdnse.print_debug("Added targets: "..prefix)
                                       		         	local status,err = target.add(prefix)
                                       		 	end
						end
					end
				end
			end
		end
		table.insert(results,prefixs)
	end
	return stdnse.format_output(true, results)
end
