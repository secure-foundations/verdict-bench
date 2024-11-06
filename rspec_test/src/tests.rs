use vstd::prelude::*;
use rspec::{rspec, test_rspec};
use rspec_lib::*;

test_rspec!(mod simple_struct1 {
    pub struct Test {
        pub a: SpecString,
        pub b: u32,
    }
});

test_rspec!(mod simple_struct2 {
    pub struct Test1 {
        pub a: SpecString,
        pub b: u32,
        pub c: Seq<u32>,
        pub d: Seq<Seq<u32>>,
    }

    pub struct Test2 {
        a: Option<Test1>,
        b: Seq<Test1>,
    }
});

test_rspec!(mod simple_function1 {
    pub closed spec fn test1(i: u32) -> bool {
        if i <= 10 {
            let a = &i + 19;
            i <= 10 && a < 100
        } else {
            true
        }
    }

    pub closed spec fn test2(i: &u32) -> bool {
        *i == 100
    }
});

test_rspec!(mod simple_function2 {
    pub closed spec fn test1(s: &SpecString) -> bool {
        &&& s.len() >= 3
        &&& s.char_at(0) == '*'
        &&& s.char_at(1) == '.'
    }

    pub closed spec fn test2(s: SpecString) -> bool {
        &&& test1(&s)
        &&& s.len() <= 5
        &&& s.char_at(2) == '*'
    }
});

test_rspec!(mod simple_function3 {
    pub closed spec fn test1(s: &SpecString) -> bool {
        &&& s.len() >= 3
        &&& s.char_at(0) == '*'
        &&& s.char_at(1) == '.'
        &&& s != "hello"@ || s == "*.haha"@
    }
});

test_rspec!(mod simple_function4 {
    pub closed spec fn test1(s: &Seq<u32>) -> bool {
        &&& s.len() != 2 - 2
        &&& s[0] == 0
    }

    pub closed spec fn test2(s: Seq<u32>) -> bool {
        test1(&s)
    }
});

test_rspec!(mod simple_function5 {
    pub closed spec fn test1(s: &Seq<u32>) -> bool {
        let a: u32 = (10 + 123) as u32;
        &&& s.len() != 2 - 2
        &&& s[0] == a
    }

    pub closed spec fn test2(s: Seq<u32>) -> bool {
        test1(&s)
    }
});

test_rspec!(mod quantifier {
    struct S {
        n: usize,
        s: SpecString,
    }

    struct Test {
        v: Seq<S>,
    }

    spec fn test_quant(t: &Test, max_len: usize) -> bool {
        forall |i: usize| #![auto] 0 <= i < t.v.len() ==> {
            &&& t.v[i as int].n == i
            &&& t.v[i as int].s.len() <= max_len
        }
    }
});

test_rspec!(mod nested_seq {
    struct Elem {
        s: SpecString,
    }

    spec fn elem_eq(e1: &Elem, e2: &Elem) -> bool {
        &e1.s == &e2.s || &e1.s == "*"@
    }

    spec fn eq(s: Seq<Seq<Elem>>, t: Seq<Seq<Elem>>) -> bool {
        &&& s.len() == t.len()
        &&& forall |i: usize| #![auto] 0 <= i < s.len() ==> {
            &&& s[i as int].len() == t[i as int].len()
            &&& forall |j: usize| #![auto] 0 <= j < s[i as int].len() ==>
                elem_eq(&s[i as int][j as int], &t[i as int][j as int])
        }
    }
});

test_rspec!(mod random_test {
    pub struct Test2 {
        pub content: SpecString,
    }

    pub struct Test3 {
        pub test2: Option<Test2>,
    }

    pub struct Test {
        pub fingerprint: SpecString,
        pub version: u32,
        pub some_seq: Seq<u32>,
        test2: Option<Test2>,
        test3: Seq<Test3>,
    }

    pub closed spec fn other(s: &u32) -> bool {
        s == 10 || *s < 100
    }

    pub closed spec fn test2(t: &Test2, s: &SpecString) -> bool {
        s.len() > 1
    }

    pub closed spec fn test(t: &Test, s: &SpecString, v: &Seq<char>, v2: Seq<char>, v3: &Seq<Seq<u32>>) -> bool {
        let a = 10u32;
        &&& t.version < a + 2
        &&& t.version >= a
        &&& v.len() > 1
        &&& v[0] == 'c'
        &&& v[1] == 'b'
        &&& s.len() > 1
        &&& s.char_at(0) == 'c'
        &&& s.char_at(1) == 'b'
        // &&& "asd"@[0] == 'a' // this doesn't work because we need reveal_lit
        &&& {
            let b = 10usize;

            &&& other(&t.version)
            &&& s.len() > b
            &&& s == "hello"@ || s == "sadsa"@ || "sadd"@ == s

            &&& t.fingerprint.len() == 16
            &&& t.fingerprint.char_at(1) == 'a'

            &&& t.some_seq.len() > 1
            &&& t.some_seq[0] == 1

            &&& "what"@ == "what"@
        }

        &&& forall |i: usize| 0 <= i < v2.len() ==> #[trigger] v2[i as int] == 'c' || v2[i as int] == 'b'
        &&& forall |i: usize| #![trigger v3[i as int]] 0 <= i < v3.len() ==> {
            forall |j: usize| 0 <= j < v3[i as int].len() ==> #[trigger] other(&v3[i as int][j as int])
        }

        &&& match &t.test2 {
            Some(t2) => test2(t2, s),
            None => false,
        }
    }
});

test_rspec!(mod test_exists {
    spec fn test(s: Seq<u32>, needle: u32) -> bool {
        exists |i: usize| 0 <= i < s.len() && s[i as int] == needle
    }
});

test_rspec!(mod test_match {
    struct Test {
        a: Option<Seq<u32>>,
    }

    spec fn all_zeros(v: &Seq<u32>) -> bool {
        forall |i: usize| 0 <= i < v.len() ==> v[i as int] == 0
    }

    spec fn test(s: Option<Option<Test>>) -> bool {
        match s {
            Some(Some(t)) => match &t.a {
                Some(v) => all_zeros(v),
                None => true,
            },
            _ => true,
        }
    }
});

test_rspec!(mod test_enum {
    enum A {
        B(u32),
        C,
        D { a: Seq<u32>, b: Option<SpecString> },
    }
});

test_rspec!(mod test_struct_unnamed {
    struct Test(u32, SpecString);
    struct UnitStruct;
    struct UnitStruct2();
});

verus! {
    rspec! {
        pub enum DirectoryName {
            CommonName(SpecString),
            Country(SpecString),
            OrganizationName(SpecString),
            OrganizationalUnit(SpecString),
            Locality(SpecString),
            State(SpecString),
            PostalCode(SpecString),
            Surname(SpecString),
        }

        pub enum GeneralName {
            DNSName(SpecString),
            DirectoryName(DirectoryName),
        }

        pub enum SubjectKey {
            RSA {
                mod_length: usize,
            },
            DSA {
                p_len: u64,
                q_len: u64,
                g_len: u64,
            },
            Other,
        }

        pub enum ExtendedKeyUsageTypes {
            ServerAuth,
            ClientAuth,
            CodeSigning,
            EmailProtection,
            TimeStamping,
            OCSPSigning,
            Any,
        }

        pub struct ExtendedKeyUsage {
            pub critical: bool,
            pub usages: Seq<ExtendedKeyUsageTypes>,
        }

        pub struct BasicConstraints {
            pub critical: bool,
            pub is_ca: bool,
            pub path_len: Option<usize>,
        }

        pub struct KeyUsage {
            pub critical: bool,
            pub digital_signature: bool,
            pub content_commitment: bool,
            pub key_encipherment: bool,
            pub data_encipherment: bool,
            pub key_agreement: bool,
            pub key_cert_sign: bool,
            pub crl_sign: bool,
            pub encipher_only: bool,
            pub decipher_only: bool,
        }

        pub struct SubjectAltName {
            pub critical: bool,
            pub names: Seq<SpecString>,
        }

        pub struct NameConstraints {
            pub critical: bool,
            pub permitted: Seq<GeneralName>,
            pub excluded: Seq<GeneralName>,
        }

        pub struct CertificatePolicies {
            pub critical: bool,
            pub policies: Seq<SpecString>,
        }

        pub struct Certificate {
            pub fingerprint: SpecString,
            pub version: u32,
            pub sig_alg: SpecString,
            pub not_after: u64,
            pub not_before: u64,

            pub subject_name: Seq<DirectoryName>,
            pub subject_key: SubjectKey,

            pub ext_extended_key_usage: Option<ExtendedKeyUsage>,
            pub ext_basic_constraints: Option<BasicConstraints>,
            pub ext_key_usage: Option<KeyUsage>,
            pub ext_subject_alt_name: Option<SubjectAltName>,
            pub ext_name_constraints: Option<NameConstraints>,
            pub ext_certificate_policies: Option<CertificatePolicies>,
        }

        pub struct Environment {
            pub time: u64,

            /// This should include all of `publicSuffix` in Hammurabi
            /// and all of their suffixes
            pub public_suffix: Seq<SpecString>,

            /// NOTE: crlSet in Hammurabi
            pub crl: Seq<SpecString>,

            /// All trusted root stores
            pub trusted: Seq<SpecString>,

            pub symantec_roots: Seq<SpecString>,
            pub symantec_exceptions: Seq<SpecString>,

            // indiaFingerprint/Domain
            pub india_trusted: Seq<SpecString>,
            pub india_domains: Seq<SpecString>,

            // anssiFingerprint/Domain
            pub anssi_trusted: Seq<SpecString>,
            pub anssi_domains: Seq<SpecString>,
        }

        pub open spec fn is_valid_pki(cert: &Certificate) -> bool {
            match cert.subject_key {
                SubjectKey::RSA { mod_length } => mod_length >= 1024,
                SubjectKey::DSA { p_len, q_len, g_len } => p_len >= 1024,
                SubjectKey::Other => true,
            }
        }

        // TODO name_match
        use exec_name_match as name_match;

        /// NOTE: leafDurationValid in Hammurabi
        pub open spec fn leaf_duration_valid(cert: &Certificate) -> bool {
            &&& cert.not_before <= cert.not_after
            &&& {
                let duration = cert.not_after - cert.not_before;

                let july_2012 = 1341100800u64;
                let april_2015 = 1427846400u64;
                let march_2018 = 1519862400u64;
                let july_2019 = 1561939200u64;
                let sep_2020 = 1598918400u64;
                let ten_years = 315532800u64;
                let sixty_months = 157852800u64;
                let thirty_nine_months = 102643200u64;
                let eight_twenty_five_days = 71280000u64;
                let three_ninety_eight_days = 34387200u64;

                ||| cert.not_before < july_2012 && cert.not_after < july_2019 && duration <= ten_years
                ||| cert.not_before >= july_2012 && cert.not_before < april_2015 && duration <= sixty_months
                ||| cert.not_before >= april_2015 && cert.not_before < march_2018 && duration <= thirty_nine_months
                ||| cert.not_before >= march_2018 && cert.not_before < sep_2020 && duration <= eight_twenty_five_days
                ||| cert.not_before >= sep_2020 && duration <= three_ninety_eight_days
            }
        }

        pub open spec fn not_in_crl(env: &Environment, cert: &Certificate) -> bool {
            forall |i: usize| 0 <= i < env.crl.len() ==> &cert.fingerprint != env.crl[i as int]
        }

        pub open spec fn strong_signature(alg: &SpecString) -> bool {
            // ECDSA + SHA512
            ||| alg == "1.2.840.10045.4.3.2"@
            // ECDSA + SHA384
            ||| alg == "1.2.840.10045.4.3.3"@
            // ECDSA + SHA512
            ||| alg == "1.2.840.10045.4.3.4"@
            // RSA + SHA256
            ||| alg == "1.2.840.113549.1.1.11"@
            // RSA + SHA384
            ||| alg == "1.2.840.113549.1.1.12"@
            // RSA + SHA512
            ||| alg == "1.2.840.113549.1.1.13"@
            // RSA-PSS + SHA256
            ||| alg == "1.2.840.113549.1.1.10"@
        }

        pub open spec fn key_usage_valid(cert: &Certificate) -> bool {
            match &cert.ext_basic_constraints {
                Some(bc) =>
                    match &cert.ext_key_usage {
                        Some(key_usage) =>
                            if bc.is_ca {
                                key_usage.key_cert_sign
                            } else {
                                !key_usage.key_cert_sign && {
                                    ||| key_usage.digital_signature
                                    ||| key_usage.key_encipherment
                                    ||| key_usage.key_agreement
                                }
                            }
                        _ => true,
                    }
                _ => true,
            }
        }

        pub open spec fn extended_key_usage_valid(cert: &Certificate) -> bool {
            match &cert.ext_extended_key_usage {
                Some(key_usage) =>
                    exists |i: usize| 0 <= i < key_usage.usages.len() &&
                        match #[trigger] key_usage.usages[i as int] {
                            ExtendedKeyUsageTypes::ServerAuth => true,
                            ExtendedKeyUsageTypes::Any => true,
                            _ => false,
                        },
                None => true,
            }
        }

        use exec_str_lower as str_lower;

        /// TODO: URI encoding, drop last '.'
        pub open spec fn clean_name(name: &SpecString) -> SpecString {
            // let lower = str_lower(name);
            // if lower.len() > 0 && lower.last() == '.' {
            //     lower.drop_last()
            // } else {
            //     lower
            // }

            str_lower(name)
        }

        // TODO
        use exec_valid_name as valid_name;

        /// Domain matches one of the SANs
        pub open spec fn domain_matches_san(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
            match &cert.ext_subject_alt_name {
                Some(subject_alt_name) => {
                    &&& subject_alt_name.names.len() > 0
                    // TODO: &env and &domain are required here due to a quirk in rspec
                    &&& forall |i: usize| #![auto] 0 <= i < subject_alt_name.names.len() ==>
                            valid_name(&env, &subject_alt_name.names[i as int])
                    &&& exists |i: usize| #![auto] 0 <= i < subject_alt_name.names.len() &&
                            name_match(&clean_name(&subject_alt_name.names[i as int]), &domain)
                }
                None => false,
            }
        }

        pub open spec fn cert_verified_leaf(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
            &&& cert.version == 2
            &&& is_valid_pki(cert)

            &&& cert.not_before < env.time
            &&& cert.not_after > env.time

            &&& domain_matches_san(env, cert, domain)

            &&& leaf_duration_valid(cert)

            &&& not_in_crl(env, cert)
            &&& strong_signature(&cert.sig_alg)
            &&& key_usage_valid(cert)
            &&& extended_key_usage_valid(cert)
        }

        pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, depth: usize) -> bool {
            &&& cert.version == 2
            &&& is_valid_pki(cert)

            &&& cert.not_before < env.time
            &&& cert.not_after > env.time

            &&& match &cert.ext_basic_constraints {
                Some(bc) => {
                    &&& bc.is_ca
                    &&& match bc.path_len {
                        Some(limit) => depth <= limit,
                        None => true,
                    }
                }
                None => false,
            }
        }

        // TODO
        use exec_valid_name_constraint as valid_name_constraint;
        use exec_permit_name as permit_name;

        /// NOTE: nameNotExcluded in Hammurabi
        pub open spec fn not_exclude_name(name_constraint: &SpecString, name: &SpecString) -> bool {
            // TODO: Check if this is equivalent to Hammmurabi
            !permit_name(name_constraint, name)
        }

        use exec_same_directory_name_type as same_directory_name_type;
        use exec_same_directory_name as same_directory_name;

        pub open spec fn has_permitted_dns_name(constraints: &NameConstraints) -> bool {
            exists |j: usize|
                0 <= j < constraints.permitted.len() &&
                match #[trigger] constraints.permitted[j as int] {
                    GeneralName::DNSName(_) => true,
                    _ => false,
                }
        }

        /// All (permitted/excluded) DNS name constraints are valid
        pub open spec fn valid_dns_name_constraints(constraints: &NameConstraints) -> bool {
            &&& forall |i: usize| 0 <= i < constraints.permitted.len() ==> {
                match #[trigger] &constraints.permitted[i as int] {
                    GeneralName::DNSName(permitted_name) => valid_name_constraint(&permitted_name),
                    _ => true,
                }
            }

            &&& forall |i: usize| 0 <= i < constraints.excluded.len() ==> {
                match #[trigger] &constraints.excluded[i as int] {
                    GeneralName::DNSName(excluded_name) => valid_name_constraint(&excluded_name),
                    _ => true,
                }
            }
        }

        /// Check a (cleaned) DNS name against name constraints
        pub open spec fn check_dns_name_constraints(name: &SpecString, constraints: &NameConstraints) -> bool {
            let name = clean_name(name);

            // Check that `name` is permitted by some name constraint in `permitted`
            &&& !has_permitted_dns_name(constraints) ||
                exists |i: usize| 0 <= i < constraints.permitted.len() && {
                    match #[trigger] &constraints.permitted[i as int] {
                        GeneralName::DNSName(permitted_name) =>
                            permit_name(&permitted_name, &clean_name(&name)),
                        _ => false,
                    }
                }

            // Check that `name` is not covered by any name constraint in `excluded`
            &&& forall |i: usize| 0 <= i < constraints.excluded.len() ==>
                match #[trigger] &constraints.excluded[i as int] {
                    GeneralName::DNSName(excluded_name) =>
                        not_exclude_name(&excluded_name, &name),
                    _ => true,
                }
        }

        /// Check the entire SAN section against name constraints
        /// NOTE: factored out due to a proof issue related to nested matches
        pub open spec fn check_san_name_constraints(san: &SubjectAltName, constraints: &NameConstraints) -> bool {
            forall |i: usize| #![auto] 0 <= i < san.names.len() ==>
                check_dns_name_constraints(
                    &clean_name(&san.names[i as int]),
                    &constraints,
                )
        }

        /// Check if there is any permitted name with the same type as the given name
        /// (if so, the permitted list is enabled)
        pub open spec fn has_permitted_dir_name_with_the_same_type(constraints: &NameConstraints, name: &DirectoryName) -> bool {
            exists |i: usize| #![trigger constraints.permitted[i as int]]
                0 <= i < constraints.permitted.len() &&
                match &constraints.permitted[i as int] {
                    GeneralName::DirectoryName(permitted_name) =>
                        same_directory_name_type(&name, &permitted_name),
                    _ => false,
                }
        }

        /// Check subject names in the leaf cert against name constraints
        pub open spec fn check_subject_name_constraints(leaf: &Certificate, constraints: &NameConstraints) -> bool {
            forall |i: usize| 0 <= i < leaf.subject_name.len() ==> {
                let leaf_name = #[trigger] &leaf.subject_name[i as int];
                let permitted_enabled = has_permitted_dir_name_with_the_same_type(&constraints, leaf_name);

                // If permitted list is enabled, check if `leaf_name`
                // is at least permitted by one of them
                &&& !permitted_enabled ||
                    exists |j: usize| 0 <= j < constraints.permitted.len() && {
                        match #[trigger] &constraints.permitted[j as int] {
                            GeneralName::DirectoryName(permitted_name) =>
                                same_directory_name(&leaf_name, &permitted_name),
                            _ => false,
                        }
                    }

                // Not explicitly excluded
                &&& forall |j: usize| 0 <= j < constraints.excluded.len() ==>
                    match #[trigger] &constraints.excluded[j as int] {
                        GeneralName::DirectoryName(excluded_name) =>
                            !same_directory_name(&leaf_name, &excluded_name),
                        _ => true,
                    }
            }
        }

        /// Check a leaf certificate against the name constraints in a parent certificate
        pub open spec fn check_name_constraints(cert: &Certificate, leaf: &Certificate) -> bool {
            match &cert.ext_name_constraints {
                Some(constraints) => {
                    &&& valid_dns_name_constraints(&constraints)
                    &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

                    // Check SAN section against name constraints
                    &&& match &leaf.ext_subject_alt_name {
                        Some(leaf_san) => check_san_name_constraints(leaf_san, constraints),
                        None => false,
                    }

                    &&& check_subject_name_constraints(leaf, constraints)
                }
                None => true,
            }
        }

        pub open spec fn cert_verified_intermediate(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
            &&& cert_verified_non_leaf(env, cert, depth)
            &&& not_in_crl(env, cert)
            &&& strong_signature(&cert.sig_alg)
            &&& key_usage_valid(cert)
            &&& extended_key_usage_valid(cert)
            &&& check_name_constraints(cert, leaf)
        }

        /// NOTE: badSymantec in Hammurabi
        pub open spec fn is_bad_symantec_root(env: &Environment, cert: &Certificate) -> bool {
            &&& exists |i: usize| 0 <= i < env.symantec_roots.len() && &cert.fingerprint == &env.symantec_roots[i as int]
            &&& forall |i: usize| 0 <= i < env.symantec_exceptions.len() ==> &cert.fingerprint != &env.symantec_exceptions[i as int]
            &&& {
                ||| cert.not_before < 1464739200 // June 2016
                ||| cert.not_before > 1512086400 // Dec 2017
            }
        }

        /// NOTE: isChromeRoot in Hammurabi
        pub open spec fn is_chrome_root(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
            &&& exists |i: usize| 0 <= i < env.trusted.len() && &cert.fingerprint == &env.trusted[i as int]

            // See fingerprintValid in Hammurabi
            &&& {
                let is_india_fingerprint = exists |i: usize| 0 <= i < env.india_trusted.len() && &cert.fingerprint == &env.india_trusted[i as int];
                let is_anssi_fingerprint = exists |i: usize| 0 <= i < env.anssi_trusted.len() && &cert.fingerprint == &env.anssi_trusted[i as int];

                &&& !is_india_fingerprint || exists |i: usize| #![auto] 0 <= i < env.india_domains.len() && name_match(&env.india_domains[i as int], &domain)
                &&& !is_anssi_fingerprint || exists |i: usize| #![auto] 0 <= i < env.anssi_domains.len() && name_match(&env.anssi_domains[i as int], &domain)
            }
        }

        pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
            &&& cert_verified_non_leaf(env, cert, depth)

            &&& match &cert.ext_key_usage {
                Some(key_usage) => key_usage.key_cert_sign,
                None => true,
            }

            &&& is_chrome_root(env, cert, domain)
            &&& !is_bad_symantec_root(env, cert)
            &&& extended_key_usage_valid(cert)
        }

        /// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
        /// chain.last() must be a trusted root
        pub open spec fn cert_verified_chain(env: &Environment, chain: &Seq<Certificate>, domain: &SpecString) -> bool
        {
            chain.len() >= 2 && {
                let leaf = &chain[0];
                let root = &chain[chain.len() - 1];

                &&& cert_verified_leaf(env, leaf, domain)
                &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> cert_verified_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
                &&& cert_verified_root(env, root, leaf, (chain.len() - 2) as usize, domain)
            }
        }
    }

    pub open spec fn name_match(pattern: &SpecString, name: &SpecString) -> bool {
        if pattern.len() > 2 && pattern[0] == '*' && pattern[1] == '.' {
            let suffix = pattern.skip(2);

            ||| suffix == name
            ||| suffix.len() + 1 < name.len() && // `name` should be longer than ".{suffix}"
                suffix == name.skip(name.len() - suffix.len()) &&
                name[name.len() - suffix.len() - 1] == '.' &&
                // the prefix of `name` that matches '*' should not contain '.'
                !name.take(name.len() - suffix.len() - 1).contains('.')
        } else {
            pattern == name
        }
    }

    #[verifier::external_body]
    pub fn exec_name_match(pattern: &String, name: &String) -> (res: bool)
        ensures res.deep_view() == name_match(&pattern.deep_view(), &name.deep_view())
    {
        // TODO
        true
    }

    pub closed spec fn str_lower(s: &SpecString) -> SpecString;

    #[verifier::external_body]
    pub fn exec_str_lower(s: &String) -> (res: String)
        ensures res.deep_view() == str_lower(&s.deep_view())
    {
        s.to_lowercase()
    }

    pub open spec fn valid_name(env: &Environment, name: &SpecString) -> bool {
        if name.contains('*') {
            &&& name.len() > 2
            &&& name[0] == '*'
            &&& name[1] == '.'
            &&& name.last() != '.'
            &&& forall |i| 0 <= i < env.public_suffix.len() ==>
                !name_match(name, #[trigger] &env.public_suffix[i])
        } else {
            &&& name.len() > 0
            &&& name[0] != '.'
            &&& name.last() != '.'
        }
    }

    #[verifier::external_body]
    pub fn exec_valid_name(env: &ExecEnvironment, name: &String) -> (res: bool)
        ensures res.deep_view() == valid_name(&env.deep_view(), &name.deep_view())
    {
        true
    }

    pub open spec fn valid_name_constraint(name: &SpecString) -> bool {
        let name = clean_name(name);
        &&& name.len() > 0
        &&& name.last() != '.'
        &&& !name.contains('*')
    }

    #[verifier::external_body]
    pub fn exec_valid_name_constraint(name: &String) -> (res: bool)
        ensures res.deep_view() == valid_name_constraint(&name.deep_view())
    {
        true
    }

    pub open spec fn permit_name(name_constraint: &SpecString, name: &SpecString) -> bool {
        ||| name_constraint.len() == 0 // empty string matches everything
        ||| if name_constraint[0] == '.' {
            // name_constraint starts with '.': name_constraint should be a suffix of name
            &&& name_constraint.len() <= name.len()
            &&& name.skip(name.len() - name_constraint.len()) == name_constraint
        } else {
            // name_constraint starts with a label: name must be the same
            // or have a suffix of '.<name_constraint>'
            ||| name == name_constraint
            ||| name.len() > name_constraint.len() &&
                name[name.len() - name_constraint.len() - 1] == '.' &&
                name.skip(name.len() - name_constraint.len()) == name_constraint
        }
    }

    #[verifier::external_body]
    pub fn exec_permit_name(name_constraint: &String, name: &String) -> (res: bool)
        ensures res.deep_view() == permit_name(&name_constraint.deep_view(), &name.deep_view())
    {
        true
    }

    pub open spec fn same_directory_name_type(name1: &DirectoryName, name2: &DirectoryName) -> bool {
        match (name1, name2) {
            (DirectoryName::CommonName(_), DirectoryName::CommonName(_)) => true,
            (DirectoryName::Country(_), DirectoryName::Country(_)) => true,
            (DirectoryName::OrganizationName(_), DirectoryName::OrganizationName(_)) => true,
            (DirectoryName::OrganizationalUnit(_), DirectoryName::OrganizationalUnit(_)) => true,
            (DirectoryName::Locality(_), DirectoryName::Locality(_)) => true,
            (DirectoryName::State(_), DirectoryName::State(_)) => true,
            (DirectoryName::PostalCode(_), DirectoryName::PostalCode(_)) => true,
            (DirectoryName::Surname(_), DirectoryName::Surname(_)) => true,
            _ => false,
        }
    }

    #[verifier::external_body]
    pub fn exec_same_directory_name_type(name1: &ExecDirectoryName, name2: &ExecDirectoryName) -> (res: bool)
        ensures res.deep_view() == same_directory_name_type(&name1.deep_view(), &name2.deep_view())
    {
        true
    }

    pub open spec fn same_directory_name(name1: &DirectoryName, name2: &DirectoryName) -> bool {
        match (name1, name2) {
            (DirectoryName::CommonName(name1), DirectoryName::CommonName(name2)) => name1 == name2,
            (DirectoryName::Country(name1), DirectoryName::Country(name2)) => name1 == name2,
            (DirectoryName::OrganizationName(name1), DirectoryName::OrganizationName(name2)) => name1 == name2,
            (DirectoryName::OrganizationalUnit(name1), DirectoryName::OrganizationalUnit(name2)) => name1 == name2,
            (DirectoryName::Locality(name1), DirectoryName::Locality(name2)) => name1 == name2,
            (DirectoryName::State(name1), DirectoryName::State(name2)) => name1 == name2,
            (DirectoryName::PostalCode(name1), DirectoryName::PostalCode(name2)) => name1 == name2,
            (DirectoryName::Surname(name1), DirectoryName::Surname(name2)) => name1 == name2,
            _ => false,
        }
    }

    #[verifier::external_body]
    pub fn exec_same_directory_name(name1: &ExecDirectoryName, name2: &ExecDirectoryName) -> (res: bool)
        ensures res.deep_view() == same_directory_name(&name1.deep_view(), &name2.deep_view())
    {
        true
    }
}

mod extern_functions {
    use super::*;

    test_rspec!(mod test {
        use exec_f as f;

        closed spec fn test() -> bool {
            &f() == "hi"@
        }
    });

    verus! {
        closed spec fn f() -> SpecString { "hi"@ }

        fn exec_f() -> (res: String)
            ensures res@ == "hi"@
        {
            "hi".to_string()
        }
    }
}
