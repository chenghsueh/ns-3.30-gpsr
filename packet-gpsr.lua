
do

    gpsr = Proto("gpsr","GPSR Protocol")

    protocoltype = ProtoField.new ( "Packet type", "gpsr.type", ftypes.UINT8)
    desposx = ProtoField.uint64 ("gpsr.dposx", "Destination Position X", base.DEC)
    desposy = ProtoField.uint64 ( "fpsr.desposy","Destination Position Y", base.DEC)
    recposx = ProtoField.uint64 ("gpsr.recposx", "Record Position X", base.DEC)
    recposy = ProtoField.uint64 ("gpsr.recposy", "Record Position Y", base.DEC)
    lastposx = ProtoField.uint64 ("gpsr.lastposx", "Source Position X", base.DEC)
    lastposy = ProtoField.uint64 ("gpsr.lastposy", "Source Position Y", base.DEC)
    time = ProtoField.uint32 ("gpsr.time", "hdrtime", base.DEC)
    reserved = ProtoField.uint8 ("gpsr.reserved", "reserved", base.DEC)

    gpsr.fields = {protocoltype, desposx, desposy, time, recposx, recposy, reserved, lastposx, lastposy}

    function gpsr.dissector(tvbuf, pkinfo, root)

        pkinfo.cols.protocol:set("GPSR")

        local tree = root:add(gpsr, tvbuf:range(0, 54))


        tree:add(protocoltype, tvbuf(0,1))
        tree:add_le(desposx, tvbuf(1, 8))
        tree:add_le(desposy, tvbuf(9, 8))
        tree:add_le(time, tvbuf(17,4))
        tree:add_le(recposx, tvbuf(21, 8))
        tree:add_le(recposy, tvbuf(29, 8))
        tree:add_le(reserved, tvbuf(37,1))
        tree:add_le(lastposx, tvbuf(38, 8))
        tree:add_le(lastposy, tvbuf(46, 8))

        local udp_dissector =   Dissector.get("udp")
        udp_dissector:call(tvbuf(54):tvb(), pkinfo, root)
    end

    DissectorTable.get("ip.proto"):add(17,gpsr)
    
end

