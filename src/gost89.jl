struct GOST89 <: BlockCipher
    key :: Vector{UInt8}
    sbox :: Vector{UInt8}
    left :: Vector{UInt8}
    right :: Vector{UInt8}
    tmp :: Vector{UInt8}
    subkey :: Vector{UInt8}
end

blocklength(E :: GOST89) = 8  # in bytes

function Magma(key :: Vector{UInt8})
    left = zeros(UInt8, 4)
    right = zeros(UInt8, 4)
    tmp = zeros(UInt8, 4)
    subkey = zeros(UInt8, 4)
    return GOST89(key, MAGMA_SBOX, left, right, tmp, subkey)
end

Magma() = Magma(zeros(UInt8, 32))
GOST89() = Magma()

# xor array2 to array 1, store in array1
function addxor!(arr1, arr2)
    for i in 1 : length(arr1)
        arr1[i] = xor(arr1[i], arr2[i])
    end
end

# shift array1 of length 4 11 bits to the left circularly
function shift11!(arr)
    tmp1 = arr[1]
    tmp2 = arr[2]
    for i in 1 : 2
        arr[i] = (arr[i + 1] << 3) | (arr[i + 2] >> 5)
    end
    arr[3] = (arr[4] << 3) | (tmp1 >> 5)
    arr[4] = (tmp1 << 3) | (tmp2 >> 5)
end

function get_encrypt_subkey!(subkey, key, roundNum)
    if roundNum <= 24
        startShift = ((roundNum - 1) % 8) * 4
    else # 24 < roundNum <= 32
        startShift = (32 - roundNum) * 4
    end
    copyto!(subkey, 1, key, startShift + 1, 4)
end

function get_decrypt_subkey!(subkey, key, roundNum)
    if roundNum <= 8
        startShift = ((roundNum - 1) % 8) * 4
    else # roundNum >= 9
        startShift = ((8 - (roundNum % 8)) % 8) * 4
    end
    copyto!(subkey, 1, key, startShift + 1, 4)
end

function add!(arr1, arr2)
    carryBit = 0
    for i in length(arr1) : -1 : 1
        byteSum = carryBit + arr1[i] + arr2[i]
        arr1[i] = UInt8(byteSum % 256)
        carryBit = div(byteSum, 256)
    end
end

# 4 u8 bits -> 4 u8 using Sbox: u4 -> u4
function sbox!(arr, sbox)
    for i in 1 : 4
        rowIndex1 = 9 - 2i
        rowIndex2 = 8 - 2i
        columnIndex1 = arr[i] >> 4 + 1
        columnIndex2 = arr[i] & 0x0f + 1
        sboxIndex1 = 16 * rowIndex1 + columnIndex1
        sboxIndex2 = 16 * rowIndex2 + columnIndex2
        arr[i] = ((sbox[sboxIndex1]) << 4) | (sbox[sboxIndex2])
    end
end

# encrypt 64-bits block txt, using key, result is written in ctxt
# txt is u8 array of length 8
function encrypt_block!(txt :: T, ctx :: GOST89, ctxt :: T) where T <: Array{UInt8}
    copyto!(ctx.left, 1, txt, 1, 4)
    copyto!(ctx.right, 1, txt, 5, 4)
    for roundNum in 1 : 32
        copyto!(ctx.tmp, ctx.right)
        get_encrypt_subkey!(ctx.subkey, ctx.key, roundNum)
        add!(ctx.right, ctx.subkey)
        sbox!(ctx.right, ctx.sbox)
        shift11!(ctx.right)
        addxor!(ctx.right, ctx.left)
        copyto!(ctx.left, ctx.tmp)
    end
    copyto!(ctxt, ctx.right)
    copyto!(ctxt, 5, ctx.left, 1, 4)
    return nothing
end

# encrypt 64-bits block ctxt, using key, result is written in txt
# ctxt is u8 array of length 8
function decrypt_block!(ctxt :: T, ctx :: GOST89, txt :: T) where T <: Array{UInt8}
    copyto!(ctx.left, 1, ctxt, 1, 4)
    copyto!(ctx.right, 1, ctxt, 5, 4)
    for roundNum in 1 : 32
        copyto!(ctx.tmp, ctx.right)
        get_decrypt_subkey!(ctx.subkey, ctx.key, roundNum)
        add!(ctx.right, ctx.subkey)
        sbox!(ctx.right, ctx.sbox)
        shift11!(ctx.right)
        addxor!(ctx.right, ctx.left)
        copyto!(ctx.left, ctx.tmp)
    end
    copyto!(txt, ctx.right)
    copyto!(txt, 5, ctx.left, 1, 4)
    return nothing
end

function encrypt_block(txt :: Array{UInt8}, ctx :: GOST89)
    ctxt = zeros(UInt8, blocklength(ctx))
    encrypt_block!(txt, ctx, ctxt)
    return ctxt
end

function decrypt_block(ctxt :: Array{UInt8}, ctx :: GOST89)
    txt = zeros(UInt8, blocklength(ctx))
    decrypt_block!(ctxt, ctx, txt)
    return txt
end

encrypt(E :: GOST89, txt :: Vector{UInt8}) = encrypt_block(txt, E)
encrypt!(txt :: Vector{UInt8}, E :: GOST89, ctxt :: Vector{UInt8}) = encrypt_block!(txt, E, ctxt)

encrypt(E :: GOST89, txt :: UInt64) = encrypt(E, u64_u8(txt))

function encrypt(E :: GOST89, pair :: NTuple)
    L, R = pair
    txt = u32_u8(L)
    append!(txt, u32_u8(R))
    encrypt(E, txt)
end

decrypt(E :: GOST89, txt :: Vector{UInt8}) = decrypt_block(txt, E)
decrypt!(ctxt :: Vector{UInt8}, E :: GOST89, txt :: Vector{UInt8}) = decrypt_block!(ctxt, E, txt)

decrypt(E :: GOST89, txt :: UInt64) = decrypt(E, u64_u8(txt))

function decrypt(E :: GOST89, pair)
    L, R = pair
    txt = u32_u8(L)
    append!(txt, u32_u8(R))
    decrypt(E, txt)
end


set_key!(E :: GOST89, key8 :: Vector{UInt8}) = (E.key .= key8)
set_key!(E :: GOST89, key32 :: Vector{UInt32}) = set_key!(E, u32_u8(key32))
set_key!(E :: GOST89, key64 :: Vector{UInt64}) = set_key!(E, u64_u8(key64))


struct MagmaInv{T <: BlockCipher} <: BlockCipher
    E :: T
end

MagmaInv() = MagmaInv(GOST89())
MagmaInv(key :: Vector{UInt8}) = MagmaInv(Magma(key))


set_key!(enc :: MagmaInv, k) = set_key!(enc.E, k)
blocklength(enc :: MagmaInv) = blocklength(enc.E)
encrypt(enc :: MagmaInv, txt) = decrypt(enc.E, txt)
encrypt!(txt, enc :: MagmaInv, ctxt) = decrypt!(txt, enc.E, ctxt)

decrypt(enc :: MagmaInv, txt) = encrypt(enc.E, txt)
decrypt!(ctxt, enc :: MagmaInv, txt) = encrypt!(ctxt, enc.E, txt)





