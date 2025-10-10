module GOSTCrypto

    include("types.jl")
    include("utils.jl")
    include("sboxes.jl")
    include("tables.jl")
    include("gost89.jl")
    include("grasshoper.jl")
    include("modes.jl")
    include("padding.jl")
    include("cryptocontext.jl")

    export Gost89, Magma
    export GrasshoperContext
    export CBC, CMAC
    export set_key!, set_iv!
    export encrypt, decrypt, mac
    export cbc_context, cmac_context
end
