# Iterable[UInt4] of length 8 is packed in one UInt32
function u4_u32(m) :: UInt32
    res = UInt32(0)
    for i in 1 : 8
        res <<= 4
        res += m[i]  # m[8-i+1]
    end
    return res 
end

# One UInt32 is splitted to Vector[UInt4] of length 8
function u32_u4(blk)
    res = zeros(UInt8, 8)
    for i in 1 : 8
        res[8-i+1] = mod(blk, 16)
        blk >>= 4
    end
    return res 
end

# One UInt64 is splitted to Vector[UInt8] of length 8
function u64_u8(v :: UInt64) :: Vector{UInt8}
    res = zeros(UInt8, 8)
    for i in 1 : 8 
        res[8-i+1] = v & 0xff
        v >>= 8
    end
    return res
end

# A vector[UInt64] is splitted to Vector[UInt8] of length 8
u64_u8(v :: Vector{UInt64}) :: Vector{UInt8} = mapreduce(u64_u8, append!, v)

function u64_u32(v :: UInt64)
    left = UInt32(v >> 32)
    right = UInt32(v & 0x00000000ffffffff)
    return [left, right]
end
u64_u32(v) = mapreduce(u64_u32, append!, v)


function u32_u8(v :: UInt32) :: Vector{UInt8}
    res = zeros(UInt8, 4)
    for i in 1 : 4
        res[5-i] = v & 0xff
        v >>= 8
    end
    return res
end
u32_u8(v :: Vector{UInt32}) = mapreduce(u32_u8, append!, v)

u32_u64(l :: UInt32, r :: UInt32) = (UInt64(l) << 32) + UInt64(r)

function u8_u32(arr :: Vector{UInt8}) :: Union{UInt32, Vector{UInt32}}
    n = length(arr)
    if n == 4
        return u8_u32_number(arr)
    else # n > 4
        return u8_u32_array(arr)
    end
end

function u8_u32_number(arr) :: UInt32
    res = UInt32(0)
    for i in 1 : 4
        res <<= 8
        res += arr[i]
    end
    return res
end

function u8_u32_array(arr :: Vector{UInt8}) :: Vector{UInt32}
    nblocks = div(length(arr),4)
    res = zeros(UInt32, nblocks)
    for i in 1 : nblocks
        res[i] = u8_u32_number(arr[4*(i-1) + 1 : 4*i])
    end
    return res
end

function u8_u64(arr :: Vector{UInt8}) :: Union{UInt64, Vector{UInt64}}
    n = length(arr)
    if n == 8
        return u8_u64_number(arr)
    else # n > 8
        return u8_u64_array(arr)
    end
end
        

function u8_u64_number(arr :: Vector{UInt8}) :: UInt64
    res = UInt64(0)
    for i in 1 : 8
        res <<= 8
        res += arr[i]
    end
    return res
end

function u8_u64_array(arr :: Vector{UInt8}) :: Vector{UInt64}
    nblocks = div(length(arr),8)
    res = zeros(UInt64, nblocks)
    for i in 1 : nblocks
        res[i] = u8_u64_number(arr[8*(i-1) + 1 : 8*i])
    end
    return res
end

msb(x :: Vector) = msb(x[1])
# up to (N-1) for UIntN
# actually we need only n = 1 and n = 4
msb(x, n) = (x >> (8 * sizeof(x) - n))
msb(x) = msb(x, 1) 


function int_to_array!(x :: Integer, arr :: Array{UInt8})
    @inbounds for i in 1 : 16
        arr[17 - i] = UInt8(x & 0xff)
        x >>= 8
    end
end

function copy_part!(from :: Array{T}, to :: Array{T}, beginIndex, howMuch) where T <: Integer
    @inbounds for i in 1 : howMuch
        to[i] = from[i + beginIndex - 1]
    end
end

function insert_part!(from :: Array{T}, to :: Array{T}, beginIndex, howMuch) where T  <: Integer
    @inbounds for i in 1 : howMuch
        to[i + beginIndex - 1] = from[i]
    end
end

