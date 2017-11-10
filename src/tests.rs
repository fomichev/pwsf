#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use item;

    #[test]
    fn invalid_db_path() {
        let mut kc = ::keychain::V3::new("invalid_db_path");
        let err = kc.unlock("invalid_password");
        assert_eq!(err.is_ok(), false);
    }

    #[test]
    fn invalid_db_password() {
        let mut kc = ::keychain::V3::new("simple.psafe3");
        let err = kc.unlock("invalid_password");
        assert_eq!(err.is_ok(), false);
    }

    #[test]
    fn valid_db_password() {
        let mut kc = ::keychain::V3::new("simple.psafe3");
        let err = kc.unlock("bogus12345");
        assert_eq!(err.is_ok(), true);
    }

    #[test]
    fn valid_db_size() {
        let mut kc = ::keychain::V3::new("simple.psafe3");
        kc.unlock("bogus12345").unwrap();
        assert_eq!(kc.len(), 9);
    }

    lazy_static! {
        pub static ref ITEMS: Vec<HashMap<item::Kind,item::Data>> = {
            let mut v = Vec::new();

            // TODO: UUID


            // 0
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1339168618));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1339168764));
            m.insert(item::Kind::Title, item::Data::Text("Test eight".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user8".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("my password".to_string()));
            m.insert(item::Kind::Notes, item::Data::Text("shift double click action set = run command".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::SClickAction, item::Data::Short(8));
            v.push(m);

            // 1
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1311392620));
            m.insert(item::Kind::AccessTime, item::Data::Int(1311400802));
            m.insert(item::Kind::ExpiryTime, item::Data::Int(1327636140));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1311907753));
            m.insert(item::Kind::Title, item::Data::Text("Test Four".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user4".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("pass4".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::PasswordPolicy, item::Data::Text("f00000e001001001001".to_string()));
            v.push(m);

            // 2
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1311386977));
            m.insert(item::Kind::AccessTime, item::Data::Int(1311400799));
            m.insert(item::Kind::ExpiryTime, item::Data::Int(1311994130));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1311907737));
            m.insert(item::Kind::Group, item::Data::Text("Test".to_string()));
            m.insert(item::Kind::Title, item::Data::Text("Test One".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user2".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("password2".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::Autotype, item::Data::Text("fdas".to_string()));
            m.insert(item::Kind::RunCommand, item::Data::Text("asdf".to_string()));
            v.push(m);

            // 3
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1339168618));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1339168719));
            m.insert(item::Kind::Title, item::Data::Text("Test seven".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user7".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("my password".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::PasswordPolicy, item::Data::Text("f00000c001001001001".to_string()));
            m.insert(item::Kind::PasswordSymbols, item::Data::Text("+_-#$%".to_string()));
            m.insert(item::Kind::Notes, item::Data::Text("Symbols set for password generation".to_string()));

            v.push(m);

            // 4
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1311386990));
            m.insert(item::Kind::AccessTime, item::Data::Int(1311400798));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1311907761));
            m.insert(item::Kind::Title, item::Data::Text("Test Two".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user3".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("pass3".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::PasswordPolicy, item::Data::Text("080000c001001001001".to_string()));
            v.push(m);

            // 5
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1339362429));
            m.insert(item::Kind::Group, item::Data::Text("Test".to_string()));
            m.insert(item::Kind::Title, item::Data::Text("Test Nine".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user9".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("DoubleClickActionTest".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::DClickAction, item::Data::Short(7));
            v.push(m);

            // 6
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1339168618));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1339168666));
            m.insert(item::Kind::Title, item::Data::Text("Test six".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user6".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("my password".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::Notes, item::Data::Text("protected entry".to_string()));
            m.insert(item::Kind::Protected, item::Data::Byte(49));
            v.push(m);

            // 7
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1311386913));
            m.insert(item::Kind::AccessTime, item::Data::Int(1311400800));
            m.insert(item::Kind::ModifyTime, item::Data::Int(1311907724));
            m.insert(item::Kind::Group, item::Data::Text("Test".to_string()));
            m.insert(item::Kind::Title, item::Data::Text("Test One".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user1".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("password1".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::PasswordPolicy, item::Data::Text("b20000b001001001001".to_string()));
            v.push(m);

            // 8
            let mut m = HashMap::new();
            m.insert(item::Kind::CreateTime, item::Data::Int(1339168618));
            m.insert(item::Kind::Title, item::Data::Text("Test Five".to_string()));
            m.insert(item::Kind::Username, item::Data::Text("user5".to_string()));
            m.insert(item::Kind::Password, item::Data::Text("my password".to_string()));
            m.insert(item::Kind::PasswordHistory, item::Data::Text("1ff00".to_string()));
            m.insert(item::Kind::Notes, item::Data::Text("email address test".to_string()));
            m.insert(item::Kind::Email, item::Data::Text("email@bogus.com".to_string()));
            v.push(m);

            v
        };
    }

    #[test]
    fn valid_db_contents() {
        let mut kc = ::keychain::V3::new("simple.psafe3");
        kc.unlock("bogus12345").unwrap();

        let mut z = 0;
        for i in kc.iter() {
            println!("{} = {:?}", z, i);

            for (k, ref v) in ITEMS[z].iter() {
                println!("? {:?}", k);
                assert_eq!(&i.get(k).unwrap(), v);
            }

            z = z + 1
        }

        assert_eq!(kc.len(), 9);
    }
}
