/// A macro which defines an enum type.
macro_rules! enum_builder {
    (
        EnumName: $enum_name: ident;
        EnumVal { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        pub enum $enum_name {
            $( $enum_var),*
            ,Unknown(u8)
        }
        impl $enum_name {
            pub fn get_u8(&self) -> u8 {
                let x = self.clone();
                match x {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
        impl Codec for $enum_name {
            fn encode(&self, bytes: &mut Vec<u8>) {
                self.get_u8().encode(bytes);
            }

            fn read(r: &mut Reader) -> Option<Self> {
                Some(match u8::read(r) {
                    None => return None,
                    $( Some($enum_val) => $enum_name::$enum_var),*
                    ,Some(x) => $enum_name::Unknown(x)
                })
            }
        }
    }
}
