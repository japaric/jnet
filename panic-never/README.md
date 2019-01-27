# `panic-never`

This crate is used to verify that the code generated for the JNeT API doesn't
contain any panicking branch where `Result` should capture all input errors
(e.g. parsing errors).
