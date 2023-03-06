/// Test for utils/crypto

#[cfg(test)]
mod crypto_main_tests {
    use nature_core::utils::Crypto;
    #[test]
    fn valid_signature() {
        let mnem = Crypto::generate_mnemonic();
        let (priv_key, pub_key) = Crypto::generate_keypair(&mnem, None).unwrap();

        let message = "Hello world!";
        let signature = Crypto::sign(message, priv_key);
        let is_valid = Crypto::is_valid(message.to_string(), signature.clone(), pub_key);
        assert!(is_valid);
    }

    #[test]
    fn invalid_signature() {
        let mnem = Crypto::generate_mnemonic();
        let (priv_key, pub_key) = Crypto::generate_keypair(&mnem, None).unwrap();
        println!("M: {}\nPR: {}\nPB: {}\n", mnem, priv_key, pub_key);
        let message = "Hello world!";
        let message_invalid = "Hello world";
        let signature = Crypto::sign(message, priv_key);
        let is_valid = Crypto::is_valid(message_invalid.to_string(), signature.clone(), pub_key);
        assert_eq!(is_valid, false)
    }

    /// Same mnemonic should be same address aka public key
    #[test]
    fn same_data() {
        let mnem = Crypto::generate_mnemonic();
        let (_, pub_first) = Crypto::generate_keypair(&mnem, None).unwrap();

        let (_, pub_second) = Crypto::generate_keypair(&mnem, None).unwrap();

        assert_eq!(pub_first, pub_second)
    }

    #[test]
    fn modified_mnemonic() {
        let mnem = "effortacab huntacab enrich cluster clip material marble long dry swear elder accident include chase episode popular stuff gas breeze pelican slight climb outside small";
        let keypair = Crypto::generate_keypair(mnem, None);
        assert!(keypair.is_err());
    }
}

#[cfg(test)]
mod crypto_cross_with_js {
    use nature_core::utils::Crypto;

    #[test]
    fn same_output_with_same_input() {
        let mnem = "effort hunt enrich cluster clip material marble long dry swear elder accident include chase episode popular stuff gas breeze pelican slight climb outside small";
        let (priv_key, pub_key) = Crypto::generate_keypair(mnem, None).unwrap();

        assert_eq!(
            priv_key,
            String::from("0fc759f889b1eecb1fc34715d55c5e77f3147e59dd7043d3dac31e143efe441f")
        );
        assert_eq!(
            pub_key,
            String::from("NATURE49cd720d44ecac34061726167af24d6f9d0a9bf9cd15dd0d469c74d82f285009")
        );
    }

    #[test]
    fn same_signature() {
        let mnem = "tray tip combine spike project wise curtain prepare stone replace dune window kid feature average art convince summer mountain virtual slogan churn blood film";
        let (pr, pb) = Crypto::generate_keypair(mnem, None).unwrap();

        let msg = "Hello world!";
        let sign = Crypto::sign(msg, pr);

        assert_eq!(sign, "ce5a451e314d9e62f2c405da13b3af7c04872016d16e7de6628fcef24c8b68c16a0a38ecdc2ea5c7426ad6f9e956bec117acf86b622444c935a2e3636d77c801");
    }

    #[test]
    fn sign_js_verify_rust() {
        let pub_key = "NATURE0ae71e0fed5ac38d900cf71de28725fb469ad7231016c6f9900dc76d02d01135";
        let sign = "7ba4252e5963735f2edf824746f8f777647bc923f1ccb7c1dd0c540c50cb7763a5208f6913c8a5db2525c7f7d9b70211b1221d32bcdedd60ebda9932959e1f03";

        let msg = "Hello world!";

        assert!(Crypto::is_valid(
            msg.to_string(),
            sign.to_string(),
            pub_key.to_string()
        ));
    }
}
