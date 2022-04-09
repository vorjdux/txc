# TXC
Text utils CLI tools

## Examples of use:
```
$ txc ue "This string will be URL encoded"
This%20string%20will%20be%20URL%20encoded.
```

```
$ echo "This string will be URL encoded" | txc ue
This%20string%20will%20be%20URL%20encoded.
```

```
$ cat Cargo.toml | txc ue
%5Bpackage%5D
name%20%3D%20%22txc%22
authors%20%3D%20%5B%22Matheus%20Santos%20%3Cvorj.dux%40gmail.com%3E%22%5D
readme%20%3D%20%22README.md%22
...
```

```
$ txc -vp ud "This%20string%20will%20be%20URL%20encoded"
-> txc::urldecode("This%20string%20will%20be%20URL%20encoded")
-> txc::result: "This string will be URL encoded"
-> txc::{took 0.3ms, sent_to_your_copy_and_paste}
```

---

## Author

Copyright [2022] Matheus Santos (vorj.dux@gmail.com)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.