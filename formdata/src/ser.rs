//! A [`serde`] serializer that flattens a value into multipart form fields.
//!
//! The only public entry point is [`to_parts`]; every serializer type below is
//! an implementation detail. The top-level value must serialize as a struct or
//! a map ([`FormSerializer`]); each field/entry is then turned into one or more
//! parts by a [`PairSerializer`]. Sequence-valued fields repeat the field name
//! once per element, and `None`/unit values are dropped.

use std::borrow::Cow;

use serde::Serialize;
use serde::ser::{self, Impossible, Serializer};

use crate::{Error, FormPart};

/// Serialize a value into a flat, ordered list of form parts.
pub(crate) fn to_parts<T>(value: &T) -> Result<Vec<FormPart>, Error>
where
    T: ?Sized + Serialize,
{
    value.serialize(FormSerializer)
}

/// Implement `Serializer` scalar methods that reject their input with `$variant`.
macro_rules! reject_scalars {
    ($variant:path; $($method:ident($ty:ty) => $found:literal),* $(,)?) => {
        $(
            fn $method(self, _value: $ty) -> Result<Self::Ok, Self::Error> {
                Err($variant($found))
            }
        )*
    };
}

// -- top level --------------------------------------------------------------

/// Serializer for the top-level form value; only structs and maps are accepted.
struct FormSerializer;

impl Serializer for FormSerializer {
    type Ok = Vec<FormPart>;
    type Error = Error;

    type SerializeSeq = Impossible<Self::Ok, Error>;
    type SerializeTuple = Impossible<Self::Ok, Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Error>;
    type SerializeMap = FormMapSerializer;
    type SerializeStruct = FormMapSerializer;
    type SerializeStructVariant = Impossible<Self::Ok, Error>;

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Ok(FormMapSerializer::with_capacity(len))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Ok(FormMapSerializer::with_capacity(len.unwrap_or(0)))
    }

    // A form may be wrapped in `Option` or a newtype; forward to the inner value.
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // An absent or unit form is simply empty.
    fn serialize_none(self) -> Result<Self::Ok, Error> {
        Ok(Vec::new())
    }

    fn serialize_unit(self) -> Result<Self::Ok, Error> {
        Ok(Vec::new())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Error> {
        Ok(Vec::new())
    }

    reject_scalars! {
        Error::TopLevel;
        serialize_bool(bool) => "a boolean",
        serialize_i8(i8) => "an integer",
        serialize_i16(i16) => "an integer",
        serialize_i32(i32) => "an integer",
        serialize_i64(i64) => "an integer",
        serialize_i128(i128) => "an integer",
        serialize_u8(u8) => "an integer",
        serialize_u16(u16) => "an integer",
        serialize_u32(u32) => "an integer",
        serialize_u64(u64) => "an integer",
        serialize_u128(u128) => "an integer",
        serialize_f32(f32) => "a float",
        serialize_f64(f64) => "a float",
        serialize_char(char) => "a character",
        serialize_str(&str) => "a string",
        serialize_bytes(&[u8]) => "bytes",
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Error> {
        Err(Error::TopLevel("an enum variant"))
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::TopLevel("an enum variant"))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(Error::TopLevel("a sequence"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(Error::TopLevel("a tuple"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(Error::TopLevel("a tuple struct"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::TopLevel("an enum variant"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::TopLevel("an enum variant"))
    }
}

// -- struct / map accumulator -----------------------------------------------

/// Accumulates parts while a struct or map is serialized as a form.
///
/// Handles both [`ser::SerializeStruct`] (static field names) and
/// [`ser::SerializeMap`] (which is also the path taken by `#[serde(flatten)]`).
struct FormMapSerializer {
    parts: Vec<FormPart>,
    key: Option<Cow<'static, str>>,
}

impl FormMapSerializer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            parts: Vec::with_capacity(capacity),
            key: None,
        }
    }
}

impl ser::SerializeStruct for FormMapSerializer {
    type Ok = Vec<FormPart>;
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(PairSerializer {
            key: Cow::Borrowed(key),
            parts: &mut self.parts,
        })
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(self.parts)
    }
}

impl ser::SerializeMap for FormMapSerializer {
    type Ok = Vec<FormPart>;
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        self.key = Some(key.serialize(KeySerializer)?);
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::Custom("serialize_value called before serialize_key".into()))?;
        value.serialize(PairSerializer {
            key,
            parts: &mut self.parts,
        })
    }

    fn serialize_entry<K, V>(&mut self, key: &K, value: &V) -> Result<(), Error>
    where
        K: ?Sized + Serialize,
        V: ?Sized + Serialize,
    {
        let key = key.serialize(KeySerializer)?;
        value.serialize(PairSerializer {
            key,
            parts: &mut self.parts,
        })
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(self.parts)
    }
}

// -- keys -------------------------------------------------------------------

/// Serializes a map key into a field name. Keys must serialize as a string.
struct KeySerializer;

/// Implement string-producing `KeySerializer` methods via [`ToString`].
macro_rules! key_to_string {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, value: $ty) -> Result<Self::Ok, Error> {
                Ok(Cow::Owned(value.to_string()))
            }
        )*
    };
}

impl Serializer for KeySerializer {
    type Ok = Cow<'static, str>;
    type Error = Error;

    type SerializeSeq = Impossible<Self::Ok, Error>;
    type SerializeTuple = Impossible<Self::Ok, Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Error>;
    type SerializeMap = Impossible<Self::Ok, Error>;
    type SerializeStruct = Impossible<Self::Ok, Error>;
    type SerializeStructVariant = Impossible<Self::Ok, Error>;

    key_to_string! {
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Error> {
        Ok(Cow::Owned(value.to_owned()))
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Error> {
        Ok(Cow::Borrowed(variant))
    }

    reject_scalars! {
        Error::UnsupportedKey;
        serialize_bytes(&[u8]) => "bytes",
    }

    fn serialize_none(self) -> Result<Self::Ok, Error> {
        Err(Error::UnsupportedKey("none"))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Error> {
        Err(Error::UnsupportedKey("a unit"))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Error> {
        Err(Error::UnsupportedKey("a unit struct"))
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        Err(Error::UnsupportedKey("an enum variant"))
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(Error::UnsupportedKey("a sequence"))
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(Error::UnsupportedKey("a tuple"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(Error::UnsupportedKey("a tuple struct"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::UnsupportedKey("an enum variant"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(Error::UnsupportedKey("a map"))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(Error::UnsupportedKey("a struct"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::UnsupportedKey("an enum variant"))
    }
}

// -- values -----------------------------------------------------------------

/// Serializes a single field value into zero or more parts under `key`.
struct PairSerializer<'a> {
    key: Cow<'static, str>,
    parts: &'a mut Vec<FormPart>,
}

impl PairSerializer<'_> {
    fn push(self, data: impl Into<Cow<'static, str>>) -> Result<(), Error> {
        self.parts.push(FormPart::new(self.key, data));
        Ok(())
    }
}

/// Implement scalar `PairSerializer` methods that push their [`ToString`] form.
macro_rules! push_to_string {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, value: $ty) -> Result<Self::Ok, Error> {
                self.push(value.to_string())
            }
        )*
    };
}

impl<'a> Serializer for PairSerializer<'a> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = SeqSerializer<'a>;
    type SerializeTuple = SeqSerializer<'a>;
    type SerializeTupleStruct = SeqSerializer<'a>;
    type SerializeTupleVariant = Impossible<(), Error>;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Impossible<(), Error>;
    type SerializeStructVariant = Impossible<(), Error>;

    push_to_string! {
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Error> {
        self.push(value.to_owned())
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Error> {
        Err(Error::UnsupportedValue("bytes"))
    }

    // `None`, unit and unit structs carry no value, so they emit no part.
    fn serialize_none(self) -> Result<Self::Ok, Error> {
        Ok(())
    }

    fn serialize_unit(self) -> Result<Self::Ok, Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Error> {
        Ok(())
    }

    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // A unit variant (e.g. a fieldless enum) serializes as its variant name.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Error> {
        self.push(variant)
    }

    // A newtype variant carries a single value; serialize it under the field name.
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    // Sequences and tuples repeat the field name once per element.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Ok(SeqSerializer {
            key: self.key,
            parts: self.parts,
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Ok(SeqSerializer {
            key: self.key,
            parts: self.parts,
        })
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Ok(SeqSerializer {
            key: self.key,
            parts: self.parts,
        })
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::UnsupportedValue("an enum tuple variant"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(Error::UnsupportedValue("a nested map"))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(Error::UnsupportedValue("a nested struct"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(Error::UnsupportedValue("an enum struct variant"))
    }
}

/// Serializes the elements of a sequence/tuple, each under the same field name.
struct SeqSerializer<'a> {
    key: Cow<'static, str>,
    parts: &'a mut Vec<FormPart>,
}

impl SeqSerializer<'_> {
    fn serialize_item<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(PairSerializer {
            key: self.key.clone(),
            parts: &mut *self.parts,
        })
    }
}

impl ser::SerializeSeq for SeqSerializer<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_item(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl ser::SerializeTuple for SeqSerializer<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_item(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}

impl ser::SerializeTupleStruct for SeqSerializer<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: ?Sized + Serialize,
    {
        self.serialize_item(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        Ok(())
    }
}
