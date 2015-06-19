local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local target = require "target"
local datafiles = require "datafiles"
local table = require "table"
local math = require "math"
local io = require "io"

description = [[
Adds IPv6 addresses to the scan queue using a wordlist of hexadecimal "words"
that form addresses in a given subnet.
]]

---
-- @usage
-- nmap -6 -p 80 --script targets-ipv6-mac --script-args newtargets,targets-ipv6-subnet={2001:db8:c0ca::/64}
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-mac:
-- |_  node count: 1254
--
-- @args targets-ipv6-mac.wordlist   File containing hexadecimal words for
--                          building addresses, one per line.  Default:
--                          nselib/data/targets-ipv6-mac
-- @args targets-ipv6-mac.nsegments  Number User can
--                           indicate exactly how big the word must be on
--                           Segments of 16 bits.
-- @args targets-ipv6-mac.fillright  With this argument
--                          the script will fill remaining zeros to the right
--                          instead of left (2001:db8:c0a:dead:: instead of
--                          2001:db8:c0ca::dead)
-- @args targets-ipv6-subnet  table/single IPv6
--                         address with prefix (Ex. 2001:db8:c0ca::/48 or
--                         { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
--  Most code is copy pasted from http://nmap.org/nsedoc/scripts/targets-ipv6-wordlist.html
--  Further work would be to migrate core functions to a libary 
--  Idea for additions from https://github.com/dragonresearchgroup/pfuzz
--  Created 19/06/2015 - v1.0 Created by John Bond <nmap@johnbond.org.>
--

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {
  "discovery"
}

local function split_prefix (net)
  local split = stdnse.strsplit("/", net)
  return split[1], tonumber(split[2])
end

local get_hextuple = function()
  hexchars = { "0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f" }
  hextuple = {}
  for _, c in ipairs(hexchars) do
    for _, d in ipairs(hexchars) do
      table.insert(hextuple, c .. d)
    end
  end
  return hextuple
end
---
-- Get a Prefix and for that one will add all the valid  words  we known.
--
-- However two arguments from the user can affect how calculated the hosts.
-- n-segments fix to pick a number of segments (by default is any segment
-- enough small for be inside of the subnet prefix) and  fill-right which alter
-- where we place the remaining zeros (Default the left).
-- @param   Direccion      String  IPv6 address (Subnet)
-- @param   Prefijo        Number  Prefix value of subnet
-- @param   TablaPalabras  Table containing all the elements to search.
-- @param   User_Segs      Number of segments to search.
-- @param   User_Right     Boolean for fill right or left (Default)
-- @return  Boolean        True if was successful the operation
-- @return  Number         Total of successfuly nodes added to the scan list.
-- @return  Error          Any error generated, default: "" not nil.
local CrearRangoHosts = function (Direccion, Prefijo, TablaPalabras,
    User_Segs, User_Right)

  local IPv6Bin, Error = ipOps.ip_to_bin(Direccion)

  if IPv6Bin == nil then
    return false, 0, Error
  end

  -- We have (128 -  n ) / ( 16 )
  -- The first part are how many bits are left to hosts portion
  -- The Second part is the size of the segments (16 bits).
  local MaxRangoSegmentos
  if User_Segs == nil then
    MaxRangoSegmentos = math.ceil((128 - Prefijo) / 16)
    User_Segs = false
  else
    MaxRangoSegmentos = tonumber(User_Segs)
  end

  stdnse.debug1("Will be calculated %d hosts for the subnet: %s/%s", #TablaPalabras, Direccion, Prefijo)

  local iTotal = 0
  -- Palabras is a table with two elements Segmento & Binario
  for Indice, Palabras in ipairs(TablaPalabras) do

    if ((tonumber(Palabras.Segmento) <= MaxRangoSegmentos) and
        User_Segs == false) or
      (User_Segs and (tonumber(Palabras.Segmento) == MaxRangoSegmentos)) then

      -- We are going to add binaries values but the question is
      -- whenever must fill with zeros?
      local Filler = string.rep("0", 128 - (Prefijo + #Palabras.Binario))

      local Host
      if User_Right ~= nil then
        Host = IPv6Bin:sub(1, Prefijo) .. Palabras.Binario .. Filler
      else
        Host = IPv6Bin:sub(1, Prefijo) .. Filler .. Palabras.Binario
      end

      -- We pass the binaries to valid IPv6
      local Error
      Host, Error = ipOps.bin_to_ip(Host)
      if Host == nil then
        -- Something is very wrong but we don-t stop
        stdnse.debug1("Failed to create IPv6 address: %s", Error)
      else
        if target.ALLOW_NEW_TARGETS then
          local bAux, sAux = target.add(Host)
          if bAux then
            iTotal = iTotal + 1
          else
            stdnse.debug1("Had been a error adding the node %s: %s", Host, sAux)
          end
        end
      end
    end
  end

  return true, iTotal
end

---
-- Parsing process of concatenate each word on the dictionary with subnetworks.
--
--@param filename The name of the file to parse
-- @return  Table     Table of elements returned (Nil if there was a error)
-- @return  String    Empty if there is no error, otherwise the error message.
local LeerArchivo = function (list)

  local Candidatos = {}
  local Registro = {
    ["Segmento"] = 0,
    ["Binario"] = "0",
  }

  for index, reg in pairs(list) do
    Registro = {
      ["Segmento"] = 0,
      ["Binario"] = "0",
    }

    Registro.Segmento = math.ceil(#reg / 4)
    Registro.Binario = ipOps.hex_to_bin(reg)
    table.insert(Candidatos, Registro)

  end

  stdnse.debug1("%d candidate words", #Candidatos)
  return Candidatos, ""
end

---
--  We get the info we need from the user and other scripts then we add them to
--  our file!
--
-- (So easy that seem we need to make them obscure)
local Prescanning = function ()
  local tSalida = {
    Nodos = 0,
    Error = "",
  }

  -- First we get the info from known prefixes because we need those Prefixes
  local IPv6PrefijoUsuario = stdnse.get_script_args "targets-ipv6-subnet"
  local User_Segs = stdnse.get_script_args "targets-ipv6-mac.nsegments"
  local User_Right = stdnse.get_script_args "targets-ipv6-mac.fillright"
  local vendor = stdnse.get_script_args "targets-ipv6-mac.vendor"
  local list = {}
  local mac_error, maclist = datafiles.parse_mac_prefixes()
  local hextuple = get_hextuple()
  if not mac_error then
    tSalida.Error = maclist
    return false, tSalida
  end
  for mac, _vendor in pairs(maclist) do
    if _vendor == vendor then
      stdnse.debug1("add mac address %s", mac)
      for _, x in ipairs(hextuple) do
        for _, y in ipairs(hextuple) do
          for _, z in ipairs(hextuple) do
            addr = mac .. 'FFFE' .. x .. y .. z
            stdnse.verbose2("add mac address %s", addr)
            table.insert(list, addr)
          end
        end
      end
    end
  end

  -- Second, we read our vital table
  local TablaPalabras, sError = LeerArchivo(list)

  if TablaPalabras == nil then
    tSalida.Error = sError
    return false, tSalida
  end

  -- We pass all the prefixes to one single table (health for the eyes)
  if IPv6PrefijoUsuario == nil then
    tSalida.Error = "There is not IPv6 subnets to try to scan!." ..
    " You can run a script for discovering or adding your own" ..
    " with the arg: targets-ipv6-subnet."
    return false, tSalida
  end

  local IPv6PrefijosTotales = {}
  if IPv6PrefijoUsuario ~= nil then
    if type(IPv6PrefijoUsuario) == "string" then
      stdnse.verbose2("Number of Prefixes Known from other sources: 1 ")
      table.insert(IPv6PrefijosTotales, IPv6PrefijoUsuario)
    elseif type(IPv6PrefijoUsuario) == "table" then
      stdnse.verbose2("Number of Prefixes Known from other sources: " .. #IPv6PrefijoUsuario)
      for _, PrefixAux in ipairs(IPv6PrefijoUsuario) do
        table.insert(IPv6PrefijosTotales, PrefixAux)
      end
    end
  end

  -- We begin to explore all thoses prefixes and retrieve our work here
  for _, PrefixAux in ipairs(IPv6PrefijosTotales) do
    local Direccion, Prefijo = split_prefix(PrefixAux)
    local bSalida, nodes, sError = CrearRangoHosts(Direccion, Prefijo,
      TablaPalabras, User_Segs, User_Right)

    if bSalida ~= true then
      stdnse.debug1("There was a error for the prefix %s: %s", PrefixAux, sError)
    end

    if sError and sError ~= "" then
      -- Not all the error are fatal for the script.
      tSalida.Error = tSalida.Error .. "\n" .. sError
    end

    tSalida.Nodos = tSalida.Nodos + nodes
  end


  return true, tSalida
end


---
-- The script need to be working with IPv6
function prerule ()
  if not (nmap.address_family() == "inet6") then
    stdnse.verbose1("Need to be executed for IPv6.")
    return false
  end

  if stdnse.get_script_args 'newtargets' == nil then
    stdnse.verbose1(" Will only work on " ..
      "pre-scanning. The argument newtargets is needed for the host-scanning" ..
      " to work.")
  end

  return true
end


function action ()

  --Vars for created the final report
  local tOutput = stdnse.output_table()

  local bExito, tSalida = Prescanning()

  -- Now we adapt the exit to tOutput and add the hosts to the target!
  if tSalida.Error and tSalida.Error ~= "" then
    tOutput.warning = tSalida.Error
    stdnse.debug1("Was unable to add nodes to the scan list due this error: %s",
      tSalida.Error)
  end

  if bExito then
    if tSalida.Nodos == 0 then
      stdnse.verbose2("No nodes were added " ..
        " to scan list! You can increase verbosity for more information" ..
        " (maybe not newtargets argument?) ")
    end
    tOutput["node count"] = tSalida.Nodos
  end


  return tOutput
end
