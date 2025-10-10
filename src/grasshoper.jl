struct GrasshoperContext <: BlockCipher
    blockLength :: Int
    masterKey :: Vector{UInt8}
    roundKeys :: Vector{UInt8}
end

blocklength(E :: GrasshoperContext) = 16  # in bytes

function GrasshoperContext(masterKey :: Vector{UInt8})
    roundKeys = zeros(UInt8, 160)
    expand_key!(masterKey, roundKeys)
    GrasshoperContext(128, masterKey, roundKeys)
end

function GrasshoperContext()
    masterKey = zeros(UInt8, 32)
    return GrasshoperContext(masterKey)
end

function set_key!(E :: GrasshoperContext, key :: Vector{UInt8})
    expand_key!(key, E.roundKeys)
    E.masterKey .= key
end


function add_key!(roundText :: Array{UInt8}, ctx :: GrasshoperContext, roundNo :: Int)
    shift = 16 * (roundNo - 1)
    @inbounds for i in 1 : 16
        roundText[i] = xor(ctx.roundKeys[i + shift], roundText[i])
    end
end

function add_key!(roundText :: Array{UInt8}, key :: Array{UInt8})
    @inbounds for i in 1 : 16
        roundText[i] = xor(key[i], roundText[i])
    end
end

function sbox_transform!(roundText :: Array{UInt8})
    @inbounds for i = 1 : 16
        roundText[i] = SBOX_STANDARD[roundText[i] + 1]
    end
end

function sbox_transform_inv!(roundText :: Array{UInt8})
    @inbounds for i = 1 : 16
        roundText[i] = SBOX_INVERSE_STANDARD[roundText[i] + 1]
    end
end

function linear_step!(roundText :: Array{UInt8})
    fieldSum = UInt8(0)
    @inbounds for i in 1 : 16
        fieldSum = xor(fieldSum, MULT_TABLE[roundText[i]*256 + LINEAR_CONSTANTS[i] + 1])
    end
    @inbounds for i in 1 : 15
        roundText[17 - i] = roundText[16 - i]
    end
    roundText[1] = fieldSum
end

function linear_step_inv!(roundText :: Array{UInt8})
    fieldSum = UInt8(0)
    @inbounds for i in 1 : 15
        fieldSum = xor(fieldSum, MULT_TABLE[roundText[i+1]*256 + LINEAR_CONSTANTS[i] + 1])
    end
    fieldSum = xor(fieldSum, MULT_TABLE[roundText[1]*256 + LINEAR_CONSTANTS[16] + 1])
    @inbounds for i in 1 : 15
        roundText[i] = roundText[i+1]
    end
    roundText[16] = fieldSum
end

function linear_transform!(roundText :: Array{UInt8})
    @inbounds for _ in 1 : 16
        linear_step!(roundText)
    end
end

function linear_transform_inv!(roundText :: Array{UInt8})
    @inbounds for _ in 1 : 16
        linear_step_inv!(roundText)
    end
end

function round_LSX!(roundText :: Array{UInt8}, roundKey :: Array{UInt8})
    # X-transformation
    add_key!(roundText, roundKey)
    # S-transformation
    sbox_transform!(roundText)
    # L-transformation
    linear_transform!(roundText)
end

function round_LSX_inv!(roundText :: Array{UInt8}, roundKey :: Array{UInt8})
    # X^(-1)-transformation
    add_key!(roundText, roundKey)
    # L^(-1)-transformation
    linear_transform_inv!(roundText)
    # S^(-1)-transformation
    sbox_transform_inv!(roundText)
end

function round_LSX!(txt :: Array{UInt8}, ctx :: GrasshoperContext, roundNo :: Int)
    # X-transformation
    add_key!(txt, ctx, roundNo)
    # S-transformation
    sbox_transform!(txt)
    # L-transformation
    linear_transform!(txt)
end

function round_LSX_inv!(txt :: Array{UInt8}, ctx :: GrasshoperContext, roundNo :: Int)
    # X-transformation
    add_key!(txt, ctx, 11 - roundNo)
    # L^(-1)-transformation
    linear_transform_inv!(txt)
    # S^(-1)-transformation
    sbox_transform_inv!(txt)
end

function feistel_round!(leftPart :: Array{UInt8}, rightPart :: Array{UInt8}, key :: Array{UInt8}, tmp3 :: Array{UInt8})
    # tmp3 = lefPart
    copyto!(tmp3, 1, leftPart, 1, 16)
    round_LSX!(leftPart, key)
    @inbounds for i in 1 : 16
        leftPart[i] = xor(leftPart[i], rightPart[i])
    end
    copyto!(rightPart, 1, tmp3, 1, 16)
    return nothing
end

function expand_key!(masterKey :: Array{UInt8}, resArray :: Array{UInt8})
    constKey = zeros(UInt8, 16)
    tmp1 = zeros(UInt8, 16)
    tmp2 = zeros(UInt8, 16)
    tmp3 = zeros(UInt8, 16)
    copyto!(resArray, 1, masterKey, 1, 32)

    @inbounds for i in 0 : 3
        copyto!(tmp1, 1, resArray, 32i + 1, 16)
        copyto!(tmp2, 1, resArray, 32i + 17, 16)
        @inbounds for j in 1 : 8
            constKey[16] = UInt8(8i + j)
            @inbounds for k in 1 : 15
                constKey[k] = UInt8(0)
            end
            linear_transform!(constKey)
            feistel_round!(tmp1, tmp2, constKey, tmp3)
        end
        copyto!(resArray, 32i + 33, tmp1, 1, 16)
        copyto!(resArray, 32i + 49, tmp2, 1, 16)
    end
end


# size of openText Array - 16 UInt8 units = 128 bits
# ctx is the Context for Grasshoper
# encrypting openText, return nothing, ciphertext is saved in cipherText
function encrypt_block!(txt :: Array{UInt8}, ctx :: GrasshoperContext, ciptxt :: Array{UInt8})
    copy!(ciptxt, txt)
    @inbounds for roundNo in 1 : 9
        round_LSX!(ciptxt, ctx, roundNo)
    end
    add_key!(ciptxt, ctx, 10)
end

# size of openText Array - 16 UInt8 units = 128 bits
# ctx is the Context for Grasshoper
# encrypting openText, return cipherText
function encrypt(openText :: Array{UInt8}, ctx :: GrasshoperContext)
    cipherText = zeros(UInt8, 16)
    encrypt_block!(openText, ctx, cipherText)
    return cipherText
end

encrypt(ctx :: GrasshoperContext, txt :: Array{UInt8}) = encrypt(txt, ctx)


# size of openText Array - 16 UInt8 units = 128 bits
# E is the Context for Grasshoper
# decrypting ctxt, return nothing, text is saved in txt
function decrypt_block!(ctxt :: Array{UInt8}, E :: GrasshoperContext, txt :: Array{UInt8})
    copy!(txt, ctxt)
    @inbounds for roundNo in 1 : 9
        round_LSX_inv!(txt, E, roundNo)
    end
    add_key!(txt, E, 1)
end

# size of openText Array - 16 UInt8 units = 128 bits
# ctx is the Context for Grasshoper
# encrypting openText, return cipherText
function decrypt(ctxt :: Array{UInt8}, E :: GrasshoperContext)
    txt = zeros(UInt8, 16)
    decrypt_block!(ctxt, E, txt)
    return txt
end

decrypt(E :: GrasshoperContext, ctxt :: Array{UInt8}) = decrypt(txt, E)





struct GrasshoperContextInv{T <: BlockCipher} <: BlockCipher
    E :: T
end

GrasshoperContextInv() = GrasshoperContextInv(GrasshoperContext())
GrasshoperContextInv(key :: Vector{UInt8}) = GrasshoperContextInv(GrasshoperContext(key))


set_key!(enc :: GrasshoperContextInv, k) = set_key!(enc.E, k)
blocklength(enc :: GrasshoperContextInv) = blocklength(enc.E)
encrypt(enc :: GrasshoperContextInv, txt) = decrypt(enc.E, txt)
encrypt!(txt, enc :: GrasshoperContextInv, ctxt) = decrypt!(txt, enc.E, ctxt)

decrypt(enc :: GrasshoperContextInv, txt) = encrypt(enc.E, txt)
decrypt!(ctxt, enc :: GrasshoperContextInv, txt) = encrypt!(ctxt, enc.E, txt)
