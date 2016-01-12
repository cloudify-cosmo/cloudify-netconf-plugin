<?xml version="1.0" encoding="utf-8"?>
<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron" queryBinding="exslt"><sch:ns uri="http://exslt.org/dynamic" prefix="dyn"/><sch:ns uri="http://example.net/turing-machine" prefix="tm"/><sch:ns uri="urn:ietf:params:xml:ns:netconf:base:1.0" prefix="nc"/><sch:let name="root" value="/nc:config"/><sch:pattern abstract="true" id="turing-machine___tape-cells"><sch:rule context="$start/$pref:cell"><sch:report test="preceding-sibling::$pref:cell[$pref:coord=current()/$pref:coord]">Duplicate key "coord"</sch:report></sch:rule></sch:pattern><sch:pattern id="turing-machine"><sch:rule context="/nc:config/tm:turing-machine/tm:transition-function/tm:delta"><sch:report test="preceding-sibling::tm:delta[tm:label=current()/tm:label]">Duplicate key "tm:label"</sch:report><sch:report test="preceding-sibling::tm:delta[tm:input/tm:state=current()/tm:input/tm:state and tm:input/tm:symbol=current()/tm:input/tm:symbol]">Violated uniqueness for "tm:input/tm:state tm:input/tm:symbol"</sch:report></sch:rule></sch:pattern><sch:pattern id="idp8148160" is-a="turing-machine___tape-cells"><sch:param name="start" value="/nc:config/tm:turing-machine/tm:tape"/><sch:param name="pref" value="tm"/></sch:pattern></sch:schema>
