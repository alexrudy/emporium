//! Models of 1Password-native types
pub mod items;
pub mod vaults;

#[doc(hidden)]
#[macro_export]
macro_rules! newtype {
    ($vis:vis $name:ident) => {

        /// A 1Password Identifier
        #[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
        $vis struct $name(Box<str>);

        impl<T> From<T> for $name
        where
            T: Into<String>,
        {
            fn from(s: T) -> Self {
                Self(s.into().into_boxed_str())
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.0.fmt(fmt)
            }
        }
    };
}
