struct Pad10 <: Padding 
    blk_len :: Int
end

pad(p :: Pad10, txt) = pad10(txt, p.blk_len)
unpad(p :: Pad10, txt) = unpad10(txt)
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



struct PadImit <: Padding 
    blk_len :: Int
end

pad(p :: PadImit, txt) = pad_imit(txt, p.blk_len)
# NB : we pad here only bytes!!

function pad_imit(txt :: Vector{UInt8}, blen)
    n = length(txt)
    taillen = (n % blen)
    if taillen != 0
        return (pad10(txt, blen), true)
    end
    return (txt, false)
end

