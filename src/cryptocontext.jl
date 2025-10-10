struct Cryptocontext{T <: BlockCipherMode, P <: Padding}
    mod :: T
    pad :: P
    need_pad :: Bool
end

set_key!(ctx :: Cryptocontext, key) = set_key!(ctx.mod, key)
set_iv!(ctx :: Cryptocontext, iv :: Vector{UInt8}) = set_iv!(ctx.mod, iv)

function encrypt(ctx :: Cryptocontext, txt)
    if ctx.need_pad
        txt = pad(ctx.pad, txt)
    end
    return encrypt(ctx.mod, txt)
end

function decrypt(ctx :: Cryptocontext, ctxt)
    txt = decrypt(ctx.mod, ctxt)
    if ctx.need_pad
        txt = unpad(ctx.pad, txt)
    end
    return txt
end

function cbc_context(; enc = Magma(), iv = zeros(UInt8, 8), pad = Pad10(blocklength(enc)), need_pad = true)
    cbc = CBC(enc, iv)
    ctx = Cryptocontext(cbc, pad, need_pad)
    return ctx
end

function cmac_context(; enc = Magma())
    pad = PadImit(blocklength(enc))
    cmac = CMAC(enc)
    ctx = Cryptocontext(cmac, pad, true)
    return ctx
end

function mac(ctx :: Cryptocontext, txt)
    txt, was_padded = pad(ctx.pad, txt)
    tag = mac(ctx.mod, txt, was_padded)
    return tag
end

