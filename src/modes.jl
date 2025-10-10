struct CBC{T} <: BlockCipherMode where {T <: BlockCipher}
    E :: T
    iv :: Vector{UInt8}
    gamma :: Vector{UInt8}
    tmp :: Vector{UInt8}
    tmpiv :: Vector{UInt8}
end

function CBC(E :: T, iv :: Vector{UInt8}) where {T <: BlockCipher}
    n = blocklength(E)
    m = length(iv)
    gamma = zeros(UInt8, n)
    tmp = zeros(UInt8, n)
    tmpiv = zeros(UInt8, m)
    return CBC(E, iv, gamma, tmp, tmpiv)
end

ivlength(mod) = length(mod.iv)
set_key!(mod, key) = set_key!(mod.E, key)
set_iv!(mod, iv :: Vector{UInt8}) = (mod.iv .= iv)
set_iv!(mod, iv :: T) where T <: Union{Vector{UInt64}, UInt64} = set_iv!(mod, u64_u8(iv))

function encrypt(cbc :: CBC, txt :: Vector{UInt8})
    ctxt = zeros(UInt8, length(txt))
    encrypt!(txt, cbc, ctxt)
    return ctxt
end

function encrypt!(txt :: Vector{UInt8}, cbc :: CBC, ctxt :: Vector{UInt8})
    # n is the block length (in bytes)
    # m is the iv length (in bytes)
    # nblocks is the number of blocks in txt
    n = blocklength(cbc.E)
    m = ivlength(cbc)
    #@assert m % n == 0
    #@assert length(txt) % n == 0
    nblocks = div(length(txt), n)
    cbc.tmpiv .= cbc.iv

    for i in 1 : nblocks
        copyto!(cbc.gamma, 1, cbc.tmpiv, 1, n)
        for j in 1 : n
            cbc.tmp[j] = xor(txt[(i-1)*n+j], cbc.gamma[j])
        end
        encrypt!(cbc.tmp, cbc.E, cbc.gamma)
        copyto!(ctxt, (i-1)*n + 1, cbc.gamma, 1, n)
        for i in 1 : (m - n)
            cbc.tmpiv[i] = cbc.tmpiv[i + n]
        end
        for i in 1 : n
            cbc.tmpiv[m - n + i] = cbc.gamma[i]
        end
    end

    return nothing
end


function decrypt!(ctxt :: Vector{UInt8}, cbc :: CBC, txt :: Vector{UInt8})
    # n is the block length (in bytes)
    # m is the iv length (in bytes)
    # nblocks is the number of blocks in ctxt
    n = blocklength(cbc.E)
    m = ivlength(cbc)
    #@assert m % n == 0
    #@assert length(ctxt) % n == 0
    nblocks = div(length(ctxt), n)
    #txt = zeros(UInt8, length(ctxt))
    #gamma = zeros(UInt8, n)
    cbc.tmpiv .= cbc.iv

    for i in 1 : nblocks
        idx = (i-1)*n+1 : i*n
        chunk = ctxt[idx]
        cbc.gamma[1:n] .= cbc.tmpiv[1:n]
        cbc.tmpiv .= circshift(cbc.tmpiv, -n)
        cbc.tmpiv[end-n+1 : end] .= chunk
        decrypt!(chunk, cbc.E, cbc.tmp)
        txt[idx] .= xor.(cbc.tmp, cbc.gamma)        
    end

    return nothing
end

function decrypt(cbc :: CBC, ctxt :: Vector{UInt8})
    txt = zeros(UInt8, length(ctxt))
    decrypt!(ctxt, cbc, txt)
    return txt
end




struct CMAC{T} <: BlockCipherMode where {T <: BlockCipher}
    E :: T
    K1 :: Vector{UInt8}
    K2 :: Vector{UInt8}
end

CMAC(E :: BlockCipher) = CMAC(E, zeros(UInt8, blocklength(E)), zeros(UInt8, blocklength(E))) 

function shift1!(x :: Vector)
    n = length(x)
    for i in 1 : (n-1)
        x[i] <<= 1
        x[i] += msb(x[i+1])
    end
    x[n] <<= 1
    return x
end

shift1(x :: Vector) = shift1!(copy(x))

function set_key!(mod :: CMAC, key :: Vector{UInt8}) 
    blen = blocklength(mod.E)
    set_key!(mod.E, key)
    R = encrypt(mod.E, zeros(UInt8, blen))
    if blen == 8
        B = zeros(UInt8, 8)
        B[end] = 0x1b
    else # blen == 16
        B = zeros(UInt8, 16)
        B[end] = 0x87
    end
    K1 = shift1(R)
    if msb(R) == 1
        K1 = xor.(K1, B)
    end
    K2 = shift1(K1)
    if msb(K1) == 1
        K2 = xor.(K2, B)
    end
    mod.K1 .= K1
    mod.K2 .= K2
end
set_key!(mod :: CMAC, key :: Vector{UInt32}) =  set_key!(mod, u32_u8(key))
set_key!(mod :: CMAC, key :: Vector{UInt64}) =  set_key!(mod, u64_u8(key))


function mac(cmac :: CMAC, txt :: Vector{UInt8}, was_padded :: Bool)
    # n is the block length (in bytes)
    # m is the iv length (in bytes)
    # nblocks is the number of blocks in txt
    n = blocklength(cmac.E)
    @assert length(txt) % n == 0
    nblocks = div(length(txt), n)
    tag = zeros(UInt8, n)
    gamma = zeros(UInt8, n)

    for i in 1 : (nblocks - 1)
        idx = (i-1)*n+1 : i*n
        gamma = xor.(txt[idx], gamma)
        gamma .= encrypt(cmac.E, gamma)
    end

    if was_padded
        Klast = cmac.K2
    else
        Klast = cmac.K1
    end

    gamma .= xor.(xor.(txt[end-n+1 : end], gamma), Klast)
    tag = encrypt(cmac.E, gamma)

    return tag
end
