/// CoAP code
macro_rules! code {
    (
        $(#[$enum_attr:meta])*
        pub enum $Enum:ident {
            $(
                #[$variant_attr:meta]
                $Variant:ident = ($class:expr, $detail:expr),
            )+
        }
    ) => {
        $(#[$enum_attr])*
        pub enum $Enum {
            $(
                #[$variant_attr]
                $Variant,
            )+
        }

        impl From<$Enum> for Code {
            fn from(e: $Enum) -> Code {
                match e {
                    $(
                        $Enum::$Variant => Code::from_parts($class, $detail),
                    )+
                }
            }
        }

        impl crate::traits::TryFrom<Code> for $Enum {
            type Error = ();

            fn try_from(c: Code) -> Result<$Enum, ()> {
                Ok(match (c.class(), c.detail()) {
                    $(
                        ($class, $detail) => $Enum::$Variant,
                    )+
                    _ => return Err(())
                })
            }
        }
    }
}

/// Enum whose variants cover the full range of the integer type `$uxx`
macro_rules! full_range {
    // Public
    ($uxx:ty,
        $(#[$enum_attr:meta])*
        pub enum $Enum:ident {
            $(
                #[$variant_attr:meta]
                $Variant:ident = $value:expr,
            )+
        }
    ) => {
        $(#[$enum_attr])*
        pub enum $Enum {
            $(
                #[$variant_attr]
                $Variant,
            )+
            /// Unknown
            Unknown($uxx),
        }

        impl From<$uxx> for $Enum {
            fn from(n: $uxx) -> $Enum {
                match n {
                    $(
                        $value => $Enum::$Variant,
                    )+
                    _ => $Enum::Unknown(n),
                }
            }
        }

        impl From<$Enum> for $uxx {
            fn from(e: $Enum) -> $uxx {
                match e {
                    $(
                        $Enum::$Variant => $value,
                    )+
                    $Enum::Unknown(n) => n,
                }
            }
        }
    };

    // Private
    ($uxx:ty,
     $(#[$enum_attr:meta])*
     enum $Enum:ident {
         $(
             $Variant:ident = $value:expr,
         )+
     }
    ) => {
        $(#[$enum_attr])*
        enum $Enum {
            $(
                $Variant,
            )+
            /// Unknown
                Unknown($uxx),
        }

        impl From<$uxx> for $Enum {
            fn from(n: $uxx) -> $Enum {
                match n {
                    $(
                        $value => $Enum::$Variant,
                    )+
                        _ => $Enum::Unknown(n),
                }
            }
        }

        impl From<$Enum> for $uxx {
            fn from(e: $Enum) -> $uxx {
                match e {
                    $(
                        $Enum::$Variant => $value,
                    )+
                        $Enum::Unknown(n) => n,
                }
            }
        }
    };
}

#[cfg(debug_assertions)]
macro_rules! debug_unreachable {
    () => {
        unreachable!()
    };
}

#[cfg(not(debug_assertions))]
macro_rules! debug_unreachable {
    () => {
        core::hint::unreachable_unchecked()
    };
}

/// Reads the bitfield of a byte / word
macro_rules! get {
    ($byte:expr, $field:ident) => {
        ($byte >> self::$field::OFFSET) & self::$field::MASK
    };
}

/// Writes to the bitfield of a byte / word
macro_rules! set {
    ($byte:expr, $field:ident, $value:expr) => {{
        let byte = &mut $byte;

        *byte &= !(self::$field::MASK << self::$field::OFFSET);
        *byte |= ($value & self::$field::MASK) << self::$field::OFFSET;
    }};
}

/// Writes to the bitfield of a byte / word
macro_rules! set_ {
    ($byte:expr, $field:ident, $value:expr) => {{
        let byte = $byte;

        *byte &= !(self::$field::MASK << self::$field::OFFSET);
        *byte |= ($value & self::$field::MASK) << self::$field::OFFSET;
    }};
}

/// Poor man's specialization
macro_rules! typeid {
    ($type_parameter:ident == $concrete_type:ident) => {
        ::core::any::TypeId::of::<$type_parameter>() == ::core::any::TypeId::of::<$concrete_type>()
    };
}
