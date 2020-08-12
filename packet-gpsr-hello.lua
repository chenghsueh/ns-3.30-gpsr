
do
    gpsr_hello = Proto("gpsr_hello", "GPSR HELLO Message")

    protocoltype = ProtoField.new ( "Packet type", "gpsr.type", ftypes.UINT8)
    posx = ProtoField.uint64 ("gpsr_hello.posx", "My Position X", base.DEC)
    posy = ProtoField.uint64 ("gpsr_hello.posy", "My Position Y", base.DEC)

    gpsr_hello.fields = {protocoltype, posx, posy}

    function gpsr_hello.dissector(tvbuf, pktinfo, root)

        pktinfo.cols.protocol:set("GPSR HELLO")

        local tree = root:add(gpsr_hello, tvbuf:range(0,17))

        tree:add(protocoltype, tvbuf(0,1))
        tree:add(posx, tvbuf(1, 8))
        tree:add(posy, tvbuf(9, 8))
        
    end
    DissectorTable.get("udp.port"):add(666, gpsr_hello) 
end