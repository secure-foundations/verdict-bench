/// High-level specs and impls of chain building and validation

use vstd::prelude::*;

#[allow(unused_imports)]
use parser::{*, x509::*, asn1::BitStringValue};

use crate::policy::{self,Policy, Task, ExecTask};
use crate::rsa;
use crate::issue::*;
use crate::error::*;

verus! {

/// Top-level spec for X509 validation
/// from certificates encoded in Base64
pub open spec fn spec_validate_x509_base64<P: Policy>(
    // Base64 encodings of trusted roots
    roots_base64: Seq<Seq<u8>>,

    // Base64 encodings of certificate chain
    // consisting of a leaf certificate (`chain[0`])
    // and intermediate certificates (`chain[1..]`)
    chain_base64: Seq<Seq<u8>>,

    policy: P,
    task: Task,
) -> bool
    recommends chain_base64.len() != 0
{
    let roots = roots_base64.map_values(|base64| spec_parse_x509_base64(base64).unwrap());
    let chain = chain_base64.map_values(|base64| spec_parse_x509_base64(base64).unwrap());

    Query {
        policy: policy,
        roots: roots,
        bundle: chain,
        task: task,
    }.valid()
}

/// An implementation for `spec_validate_x509_base64`
/// Note that it's recommended to cache the result of creating
/// a `RootStore` and `Validator` for better performance without
/// processing roots every time.
pub fn validate_x509_base64<P: Policy>(
    roots_base64: &Vec<Vec<u8>>,
    chain_base64: &Vec<Vec<u8>>,

    policy: P,
    task: &ExecTask,
) -> (res: Result<bool, ValidationError>)
    requires chain_base64@.len() != 0
    ensures
        res matches Ok(res) ==> res == spec_validate_x509_base64(
            roots_base64.deep_view(),
            chain_base64.deep_view(),
            policy,
            task.deep_view(),
        ),
{
    let store = RootStore::from_base64(roots_base64)?;
    let validator = Validator::from_root_store(policy, &store)?;
    let res = validator.validate_base64(chain_base64, task)?;

    // Some conversions from deep_view and view
    assert(roots_base64.deep_view() =~~= roots_base64@.map_values(|base64: Vec<u8>| base64@));
    assert(chain_base64.deep_view() =~~= chain_base64@.map_values(|base64: Vec<u8>| base64@));

    assert(validator.roots@ =~= roots_base64.deep_view().map_values(|base64: Seq<u8>| spec_parse_x509_base64(base64).unwrap()));
    assert(
        chain_base64@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap())
        =~~=
        chain_base64.deep_view().map_values(|base64| spec_parse_x509_base64(base64).unwrap())
    );

    Ok(res)
}

pub struct Query<P: Policy> {
    pub policy: P,
    pub roots: Seq<SpecCertificateValue>,

    /// `bundle[0]` is the leaf certificate
    pub bundle: Seq<SpecCertificateValue>,

    /// Hostname validation, chain validation, etc.
    pub task: Task,
}

/// High-level specifications for when a query is valid
impl<P: Policy> Query<P> {
    pub open spec fn is_simple_path(self, path: Seq<usize>) -> bool {
        &&& path.len() != 0
        &&& path[0] == 0 // starts from the leaf (i.e. `bundle[0]`)

        // `path` contains unique indices into `self.bundle`
        &&& forall |i| 0 <= i < path.len() ==> 0 <= #[trigger] path[i] < self.bundle.len()
        &&& forall |i, j| 0 <= i < path.len() && 0 <= j < path.len() && i != j ==> path[i] != path[j]

        // `path` = bundle[path[0]] -> ... -> bundle[path.last()]
        &&& forall |i: int| #![trigger path[i]] 0 <= i < path.len() - 1 ==>
            spec_likely_issued(self.bundle[path[i + 1] as int], self.bundle[path[i] as int])
    }

    /// `path` is a valid simple path from `path[0]` to reach a root certificate
    pub open spec fn is_simple_path_to_root(self, path: Seq<usize>, root_idx: usize) -> bool {
        &&& 0 <= root_idx < self.roots.len()
        &&& self.is_simple_path(path)
        &&& spec_likely_issued(self.roots[root_idx as int], self.bundle[path.last() as int])
    }

    /// Check if the candidate chain satisfies the policy constraints
    pub open spec fn path_satisfies_policy(self, path: Seq<usize>, root_idx: usize) -> bool {
        let candidate = path.map_values(|i| self.bundle[i as int]) + seq![self.roots[root_idx as int]];
        let abstract_candidate = candidate.map_values(|cert| policy::Certificate::spec_from(cert).unwrap());

        self.policy.spec_valid_chain(abstract_candidate, self.task) matches Ok(res) && res
    }

    pub open spec fn valid(self) -> bool {
        &&& self.bundle.len() != 0
        &&& exists |path: Seq<usize>, root_idx: usize| {
            &&& self.is_simple_path_to_root(path, root_idx)
            &&& self.path_satisfies_policy(path, root_idx)
        }
    }
}

pub struct Validator<'a, P: Policy> {
    pub policy: P,
    pub roots: VecDeep<CertificateValue<'a>>,
    pub roots_rsa_cache: Vec<Option<rsa::RSAPublicKeyInternal>>,
}

impl<'a, P: Policy> Validator<'a, P> {
    #[verifier::loop_isolation(false)]
    pub fn new(policy: P, roots: VecDeep<CertificateValue<'a>>) -> (res: Self)
        ensures
            res.wf(),
            res.policy == policy,
            res.roots == roots,
    {
        let roots_len = roots.len();
        let mut roots_rsa_cache = Vec::with_capacity(roots_len);

        // Initialize the RSA key cache by parsing
        // the RSA public key of each root certificate
        for i in 0..roots_len
            invariant
                i == roots_rsa_cache@.len(),
                forall |i| 0 <= i < roots_rsa_cache@.len() ==>
                    (#[trigger] roots_rsa_cache@[i] matches Some(key) ==> {
                        let subject_key = roots@[i].cert.subject_key;
                        &&& subject_key.alg.param is RSAEncryption
                        &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(subject_key.pub_key)) == Some(key)
                    })
        {
            let root = roots.get(i);

            roots_rsa_cache.push(if let AlgorithmParamValue::RSAEncryption(..) = &root.get().cert.get().subject_key.alg.param {
                let pub_key = root.get().cert.get().subject_key.pub_key.bytes();

                match rsa::pkcs1_v1_5_load_pub_key(pub_key) {
                    Ok(pub_key) => Some(pub_key),

                    // NOTE: skip if the pub key of a root certificate fail to parse
                    Err(..) => None,
                }
            } else {
                None
            });
        }

        Validator { policy, roots, roots_rsa_cache }
    }

    /// Initialize a validator from a root store
    pub fn from_root_store(policy: P, store: &'a RootStore) -> (res: Result<Self, ValidationError>)
        ensures
            res matches Ok(res) ==> {
                &&& res.wf()
                &&& res.policy == policy
                &&& res.roots@ =~= store.roots_der@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap())
            }
    {
        let roots_len = store.roots_der.len();
        let mut roots = VecDeep::with_capacity(roots_len);

        for i in 0..roots_len
            invariant
                roots_len == store.roots_der@.len(),
                i == roots@.len(),
                forall |i| 0 <= i < roots@.len() ==>
                    spec_parse_x509_der(store.roots_der@[i]@) == Some(#[trigger] roots@[i]),
        {
            roots.push(parse_x509_der(store.roots_der[i].as_slice())?);
        }

        Ok(Self::new(policy, roots))
    }

    pub closed spec fn wf(self) -> bool {
        &&& self.roots_rsa_cache@.len() == self.roots@.len()
        &&& forall |i| 0 <= i < self.roots@.len() ==>
            (#[trigger] self.roots_rsa_cache@[i] matches Some(key) ==> {
                let subject_key = self.roots@[i].cert.subject_key;

                &&& subject_key.alg.param is RSAEncryption
                &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(subject_key.pub_key)) == Some(key)
            })
    }

    closed spec fn is_prefix_of<T>(s1: Seq<T>, s2: Seq<T>) -> bool {
        &&& s1.len() <= s2.len()
        &&& forall |i| 0 <= i < s1.len() ==> #[trigger] s1[i] == #[trigger] s2[i]
    }

    fn has_node(path: &Vec<usize>, node: usize) -> (res: bool)
        ensures res == path@.contains(node)
    {
        let path_len = path.len();

        for i in 0..path_len
            invariant
                path_len == path@.len(),
                forall |j| 0 <= j < i ==> path@[j] != node,
        {
            if path[i] == node {
                return true;
            }
        }

        return false;
    }

    /// A specialized version of `likely_issued`
    /// that uses RSA public key cache of root certs
    fn check_root_likely_issued(&self, idx: usize, subject: &CertificateValue) -> (res: bool)
        requires
            self.wf(),
            0 <= idx < self.roots@.len(),

        ensures res == spec_likely_issued(self.roots@[idx as int], subject@)
    {
        let root = self.roots.get(idx);

        if let Some(pub_key) = &self.roots_rsa_cache[idx] {
            if !same_name(&root.get().cert.get().subject, &subject.get().cert.get().issuer) {
                return false;
            }

            // Mostly the same as the RSA branch of `verify_signature`
            let tbs_cert = subject.get().cert.serialize();
            let sig_alg = &subject.get().sig_alg.get();
            let sig = subject.get().sig.bytes();

            if sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
                return rsa::pkcs1_v1_5_verify(sig_alg, &pub_key, sig, tbs_cert).is_ok();
            }

            return false;
        }

        likely_issued(root, subject)
    }

    pub open spec fn get_query(
        &self,
        bundle: Seq<SpecCertificateValue>,
        task: policy::Task,
    ) -> Query<P> {
        Query {
            policy: self.policy,
            roots: self.roots@,
            bundle: bundle,
            task: task,
        }
    }

    /// Check if a candidate path satisfies the policy
    /// TODO: cache `policy::Certificate::from` results
    fn check_chain_policy(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &ExecTask,
        path: &Vec<usize>,
        root_idx: usize,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx),

        ensures
            res matches Ok(res) ==>
                res == self.get_query(bundle@, task.deep_view()).path_satisfies_policy(path@, root_idx),
    {
        let path_len = path.len();
        if path_len == usize::MAX {
            return Err(ValidationError::IntegerOverflow);
        }

        let mut candidate: Vec<policy::ExecCertificate> = Vec::with_capacity(path_len + 1);

        // Convert the entire path to `ExecCertificate`
        for i in 0..path_len
            invariant
                path_len == path@.len(),
                self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx),

                candidate@.len() == i,
                forall |j| #![trigger candidate@[j]] 0 <= j < i ==>
                    Some(candidate@[j].deep_view()) == policy::Certificate::spec_from(bundle@[path@[j] as int]),
        {
            candidate.push(policy::Certificate::from(bundle.get(path[i]))?);
        }

        // Append the root certificate
        candidate.push(policy::Certificate::from(self.roots.get(root_idx))?);

        assert(candidate.deep_view() =~=
            (path@.map_values(|i| bundle@[i as int]) + seq![self.roots@[root_idx as int]])
                .map_values(|cert| policy::Certificate::spec_from(cert).unwrap()));

        match self.policy.valid_chain(&candidate, task) {
            Ok(res) => Ok(res),
            Err(err) => Err(ValidationError::PolicyError(err)),
        }
    }

    /// Given a simple path through the bundle certificates
    /// and all root issuers of the last certificate in the path,
    /// check if the entire path satisfies the policy
    #[verifier::loop_isolation(false)]
    fn check_simple_path(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &policy::ExecTask,

        path: &Vec<usize>,
        root_issuers: &Vec<usize>,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.get_query(bundle@, task.deep_view()).is_simple_path(path@),
            self.spec_root_issuers(bundle@[path@.last() as int], root_issuers@),

        ensures
            res matches Ok(res) ==>
                res == exists |root_idx: usize|
                    #[trigger] self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx) &&
                    self.get_query(bundle@, task.deep_view()).path_satisfies_policy(path@, root_idx)
    {
        reveal(Validator::spec_root_issuers);

        let root_issuers_len = root_issuers.len();
        let ghost query = self.get_query(bundle@, task.deep_view());

        for i in 0..root_issuers_len
            invariant
                forall |j| 0 <= j < i ==>
                    !query.path_satisfies_policy(path@, #[trigger] root_issuers@[j]),
        {
            if self.check_chain_policy(bundle, task, &path, root_issuers[i])? {
                // Found a valid chain
                return Ok(true);
            }
        }

        assert forall |root_idx: usize|
            #[trigger] query.is_simple_path_to_root(path@, root_idx) implies
            !query.path_satisfies_policy(path@, root_idx)
        by {
            assert(root_issuers@.contains(root_idx));
        }

        Ok(false)
    }

    closed spec fn get_root_indices(self) -> Seq<usize> {
        Seq::new(self.roots@.len() as nat, |i| i as usize)
    }

    #[verifier::opaque]
    closed spec fn spec_root_issuers(self, cert: SpecCertificateValue, indices: Seq<usize>) -> bool {
        // All in-bound
        &&& forall |i| 0 <= i < indices.len() ==> 0 <= #[trigger] indices[i] < self.roots@.len()

        // Contains all likely root issuers
        &&& forall |i| 0 <= i < self.roots@.len() &&
            spec_likely_issued(self.roots@[i as int], cert) ==>
            #[trigger] indices.contains(i)

        // Only contains likely root issuers
        &&& forall |i| 0 <= i < indices.len() ==>
            spec_likely_issued(self.roots@[#[trigger] indices[i] as int], cert)
    }

    /// Get indices of root certificates that likely issued the given certificate
    #[verifier::loop_isolation(false)]
    fn get_root_issuer(&self, cert: &CertificateValue) -> (res: Vec<usize>)
        requires self.wf()
        ensures self.spec_root_issuers(cert@, res@)
    {
        let mut res = Vec::with_capacity(1); // usually there is only 1 root issuer
        let roots_len = self.roots.len();

        let ghost pred = |j: usize| spec_likely_issued(self.roots@[j as int], cert@);

        for i in 0..roots_len
            invariant
                forall |i| 0 <= i < res.len() ==> 0 <= #[trigger] res[i] < self.roots@.len(),
                res@ =~= self.get_root_indices().take(i as int).filter(pred),
        {
            reveal_with_fuel(Seq::<_>::filter, 1);

            if self.check_root_likely_issued(i, cert) {
                res.push(i);
            }

            assert(self.get_root_indices().take(i + 1).drop_last() =~= self.get_root_indices().take(i as int));
        }

        assert(self.get_root_indices().take(roots_len as int) == self.get_root_indices());

        assert forall |i|
            0 <= i < self.roots@.len() &&
            spec_likely_issued(self.roots@[i as int], cert@)
            implies #[trigger] res@.contains(i)
        by {
            assert(self.get_root_indices()[i as int] == i);
            assert(pred(self.get_root_indices()[i as int]));
        }

        reveal(Validator::spec_root_issuers);

        res
    }

    /// Validate a leaf certificate (bundle[0]) against
    /// a task and try to build a valid chain through
    /// the `bundle` of intermediate certificates
    #[verifier::loop_isolation(false)]
    pub fn validate(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &policy::ExecTask,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==> res == self.get_query(bundle@, task.deep_view()).valid(),
    {
        let bundle_len = bundle.len();

        // root_issuers[i] are the indices of root certificates that likely issued bundle[i]
        let mut root_issuers: Vec<Vec<usize>> = Vec::with_capacity(bundle_len);

        // Collect all root issuers for each certificate in the bundle
        for i in 0..bundle_len
            invariant
                root_issuers@.len() == i,
                forall |j| 0 <= j < i ==>
                    self.spec_root_issuers(bundle@[j], #[trigger] root_issuers@[j]@),
        {
            root_issuers.push(self.get_root_issuer(bundle.get(i)));
        }

        let ghost query = self.get_query(bundle@, task.deep_view());

        // DFS from bundle[0] to try to reach a root
        // Stack of path prefices to explore
        let mut stack: Vec<Vec<usize>> = vec![ vec![ 0 ] ];

        // For triggering quantifiers associated with the leaf
        let ghost _ = stack@[0]@;

        loop
            invariant
                forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),

                // For completeness: any simple path not prefixed by elements in
                // the current stack should be already confirmed as invalid
                forall |path: Seq<usize>, root_idx: usize|
                    #[trigger] query.is_simple_path_to_root(path, root_idx) &&
                    (forall |i| 0 <= i < stack.len() ==>
                        !Self::is_prefix_of(#[trigger] stack@[i]@, path))
                    ==>
                    !query.path_satisfies_policy(path, root_idx),
        {
            let ghost prev_stack = stack@;

            if let Some(cur_path) = stack.pop() {
                let last = cur_path[cur_path.len() - 1];

                if self.check_simple_path(bundle, task, &cur_path, &root_issuers[last])? {
                    return Ok(true);
                }

                // Push any extension of `path` that is still a simple path
                for i in 0..bundle_len
                    invariant
                        stack@.len() >= prev_stack.len() - 1,
                        forall |i| 0 <= i < prev_stack.len() - 1 ==>
                            stack@[i] == #[trigger] prev_stack[i],

                        // For any other `path` prefixed by `cur_path` (and longer than it)
                        // either `path` is prefixed by some path in the stack
                        // or `path`'s next node >= i
                        forall |path: Seq<usize>|
                            #[trigger] Self::is_prefix_of(cur_path@, path) &&
                            query.is_simple_path(path) &&
                            path.len() > cur_path@.len() &&
                            path[cur_path@.len() as int] < i
                            ==>
                            exists |j| 0 <= j < stack@.len() && Self::is_prefix_of(#[trigger] stack@[j]@, path),

                        // Stack invariant: all paths in the stack are simple paths
                        forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),
                {
                    let ghost prev_stack = stack@;

                    if !Self::has_node(&cur_path, i) && likely_issued(bundle.get(i), bundle.get(last)) {
                        let mut next_path = Clone::clone(&cur_path);
                        next_path.push(i);
                        stack.push(next_path);
                    }

                    assert forall |path: Seq<usize>|
                        #[trigger] Self::is_prefix_of(cur_path@, path) &&
                        query.is_simple_path(path) &&
                        path.len() > cur_path@.len() &&
                        path[cur_path@.len() as int] < i + 1
                        implies
                        exists |j| 0 <= j < stack@.len() && Self::is_prefix_of(#[trigger] stack@[j]@, path)
                    by {
                        if path[cur_path@.len() as int] == i {
                            if cur_path@.contains(i) {
                                // Not a simple path
                                let k = choose |k| 0 <= k < cur_path@.len() && cur_path@[k] == i;
                                assert(path[k] == i);
                            } else if !spec_likely_issued(bundle@[i as int], bundle@[last as int]) {
                                // Not a path
                                assert(path[cur_path@.len() - 1] == i);
                            } else {
                                // Path was just added
                                assert(Self::is_prefix_of(stack@[stack@.len() - 1]@, path));
                            }
                        } else {
                            // By loop invariant
                            let k = choose |k| 0 <= k < prev_stack.len() && Self::is_prefix_of(#[trigger] prev_stack[k]@, path);
                            assert(stack@[k] == prev_stack[k]);
                        }
                    }
                }

                // Check the completeness invariant
                // For any path starting `bundle[0]`
                // that does NOT have any of the stack
                // elements as prefix, should not have
                // a simple valid path to a root
                assert forall |path: Seq<usize>, root_idx: usize|
                    #[trigger] query.is_simple_path_to_root(path, root_idx) &&
                    (forall |i| 0 <= i < stack.len() ==>
                        !Self::is_prefix_of(#[trigger] stack@[i]@, path))
                    implies
                    // No valid simple path to root
                    !query.path_satisfies_policy(path, root_idx)
                by {
                    if !Self::is_prefix_of(cur_path@, path) {
                        assert(forall |i| 0 <= i < prev_stack.len()
                            ==> !Self::is_prefix_of(#[trigger] prev_stack[i]@, path));
                    } else {
                        if path.len() <= cur_path@.len() {
                            assert(path =~= cur_path@);
                            // By post-condition of check_simple_path
                        } // else by LI of the inner loop
                    }
                }

            } else {
                // assert(forall |path: Seq<usize>, root_idx: usize|
                //     #[trigger] query.is_simple_path_to_root(path, root_idx) ==>
                //     !query.path_satisfies_policy(path, root_idx));
                // assert(!query.valid());
                return Ok(false);
            }
        }
    }

    /// Same as `validate`, but parses certificates from DER
    pub fn validate_der(&self, bundle: &Vec<Vec<u8>>, task: &policy::ExecTask) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==>
                res == self.get_query(
                    bundle@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap()),
                    task.deep_view(),
                ).valid(),
    {
        let bundle_len = bundle.len();
        let mut bundle_parsed: VecDeep<CertificateValue> = VecDeep::with_capacity(bundle_len);

        for i in 0..bundle_len
            invariant
                bundle_len == bundle@.len(),
                bundle_parsed@.len() == i,
                forall |j| 0 <= j < i ==> spec_parse_x509_der(bundle@[j]@) == Some(#[trigger] bundle_parsed@[j]),
        {
            bundle_parsed.push(parse_x509_der(bundle[i].as_slice())?);
        }
        assert(bundle_parsed@ =~= bundle@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap()));

        self.validate(&bundle_parsed, task)
    }

    /// Same as `validate`, but parses certificates from Base64
    pub fn validate_base64(&self, bundle: &Vec<Vec<u8>>, task: &policy::ExecTask) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==>
                res == self.get_query(
                    bundle@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap()),
                    task.deep_view(),
                ).valid(),
    {
        let bundle_len = bundle.len();
        let mut bundle_der: Vec<Vec<u8>> = Vec::with_capacity(bundle_len);

        for i in 0..bundle_len
            invariant
                bundle_len == bundle@.len(),
                bundle_der@.len() == i,
                forall |j| 0 <= j < i ==> spec_decode_base64(bundle@[j]@) == Some(#[trigger] bundle_der@[j]@),
        {
            bundle_der.push(decode_base64(bundle[i].as_slice())?);
        }

        assert(
            bundle_der@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap())
            =~=
            bundle@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap())
        );

        self.validate_der(&bundle_der, task)
    }
}

pub struct RootStore {
    /// DER encodings of all root certificates
    pub roots_der: Vec<Vec<u8>>,
}

impl RootStore {
    /// Creates a root store from base64 encodings of root certificates
    pub fn from_base64(roots_base64: &Vec<Vec<u8>>) -> (res: Result<RootStore, ParseError>)
        ensures
            res matches Ok(res) ==> {
                &&& res.roots_der@.len() == roots_base64.len()
                &&& forall |i| 0 <= i < roots_base64@.len() ==>
                        spec_decode_base64(#[trigger] roots_base64@[i]@) == Some(res.roots_der@[i]@)
            },
            res is Err ==>
                exists |i| 0 <= i < roots_base64.len() &&
                    spec_decode_base64(#[trigger] roots_base64@[i]@) is None,
    {
        let mut roots_der: Vec<Vec<u8>> = Vec::with_capacity(roots_base64.len());
        let len = roots_base64.len();

        for i in 0..len
            invariant
                len == roots_base64@.len(),
                roots_der@.len() == i,
                forall |j| 0 <= j < i ==>
                    spec_decode_base64(#[trigger] roots_base64@[j]@) == Some(roots_der@[j]@),
        {
            roots_der.push(decode_base64(roots_base64[i].as_slice())?);
        }

        Ok(RootStore { roots_der })
    }
}

}
