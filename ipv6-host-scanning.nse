description = [[
Produces a list of prefixes for a given ASN.

This script uses a whois server database operated by the Shadowserver
Foundation.  We thank them for granting us permission to use this in
Nmap.

Output is in CIDR notation. If the <code>newtargets</code> script
argument is given, all discovered prefixes will be added to the Nmap
target list for scanning.

http://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP
]]

---
-- @args asn-to-prefix.asn The ASN to search.
-- @args asn-to-prefix.whois_server The whois server to use. Default: asn.shadowserver.org.
-- @args asn-to-prefix.whois_port The whois port to use. Default: 43.
-- @args newtargets Add discovered targets to Nmap scan queue.
--
-- @usage
-- nmap --script asn-to-prefix --script-args asn-to-prefix.asn=32
--
-- @output
-- 53/udp open  domain  udp-response
-- | asn-to-prefix:
-- |   32
-- |     128.12.0.0/16
-- |_    171.64.0.0/14

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "external", "safe"}

require "stdnse"
require "shortport"
require "target"

prerule = function()
	return true
end

local function oui_scan(ipv6prefix,oui_vendor)
end

local function vendor_scan(ipv6prefix,vendor)
end

local function ipv4prefix_scan(ipv6prefix,ipv4prefix)
end

local function toredo_scan(ipv6prefix)
end

local function 6to4_scan(ipv6prefix)
end

local function byte_scan(ipv6prefix,start,bits)
end

local function word_scan(ipv6prefix,start,bits)
end

action = function(host, port)
	local ipv6host = {}
	local results = {}
        local ipv6prefix = stdnse.get_script_args(SCRIPT_NAME .. '.ipv6prefix')
        local ipv4prefix = stdnse.get_script_args(SCRIPT_NAME .. '..ipv4prefix')
        local oui_vendor = stdnse.get_script_args(SCRIPT_NAME .. '..oui_vendor')
        local vendor = stdnse.get_script_args(SCRIPT_NAME .. '..vendor')
        local lowbyte_bits = stdnse.get_script_args(SCRIPT_NAME .. '..lowbyte_bits')
        local word_scan = stdnse.get_script_args(SCRIPT_NAME .. '..word_scan')
        local 6to4_scan = stdnse.get_script_args(SCRIPT_NAME .. '..6to4_scan')
        local toredo_scan = stdnse.get_script_args(SCRIPT_NAME .. '..toredo_scan')

        if ( not(ipv6prefix) ) then
            return fail(SCRIPT_NAME .. ".ipv6prefix not specified")
        end
        if ipv4prefix then
            ipv6host = ipv4prefix_scan(ipv6prefix,ipv4prefix)
        end
        if oui_vendor then
            ipv6host = oui_scan(ipv6prefix,oui_vendor)
        end
        if vendor then
            ipv6host = vendor_scan(ipv6prefix,vendor)
        end
        if lowbyte_bits then
            ipv6host = byte_scan(ipv6prefix,0,lowbyte_bits)
        end
        if word_scan then
            ipv6host = word_scan(ipv6prefix)
        end
        if 6to4_scan then
            if ( not(ipv4prefix) ) then
                return fail(SCRIPT_NAME .. ".ipv4prefix not specified")
            end
            ipv6host = 6to4_scan(ipv6prefix,ipv4prefix)
        end
        if toredo_scan then
            if ( not(ipv4prefix) ) then
                return fail(SCRIPT_NAME .. ".ipv4prefix not specified")
            end
            ipv6host = toredo_scan(ipv6prefix,ipv4prefix)
        end
	return stdnse.format_output(true, results)
end
