struct Pad10 <: Padding 
    blk_len :: Int
end

pad(p :: Pad10, txt) = pad10(txt, p.blen)
unpad(p :: Pad10, ctxt) = unpad10(txt)
# NB : we pad here only bytes!!

function pad10(txt :: Vector{UInt8}, blen)
    # blen = block length in bytes
    ptxt = copy(txt)
    n = length(txt)
    padlen = blen - (n % blen)
    if padlen == 0
        padlen = blen
    end
    padding = [0x80]
    append!(padding, zeros(UInt8, padlen - 1))
    append!(ptxt, padding)
    return ptxt
end


function unpad10(txt :: Vector{UInt8})
    # blen = block length in bytes
    uptxt = copy(txt)
    while uptxt[end] == 0x00
        pop!(uptxt)
    end 
    pop!(uptxt)
    return uptxt
end

