use bytes::Bytes;
use std::env;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zplc::compilation::{CompilationBuilder, OutputFormat};
use zplc::dumpv2::dump_v2;
use zpr::policy::v1 as policy_capnp;
use zpr::policy_types::TrustedService;

fn get_zpl_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir).join("test-data")
}

struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).expect("failed to remove zpc temp dir");
    }
}

impl TempDir {
    fn new(name_hint: &str) -> Self {
        let mut temp_dir = env::temp_dir();
        temp_dir.push(format!(
            "zpl-test-{}-{}-{}",
            name_hint,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir for zpc output");
        TempDir { path: temp_dir }
    }
}

#[test]
fn can_parse_rfc_examples() {
    let zpl_dir = get_zpl_dir();
    let config_file = zpl_dir.join("config.zplc");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list zpl test directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // And must start with "rfc"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("rfc") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .parse_only(true)
                    .output_format(*outfmt)
                    .config(&config_file);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

#[test]
fn can_compile_m3_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("m3");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list M3 policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "m3-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("m3-") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// Make sure we can still compile the policies in the
// integration-test. Note that this does not try to compile
// with the IPv6 config used there.
#[test]
fn can_compile_integtest_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("integtest");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list integration-test policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "integ-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("m3") {
                        continue;
                    }
                }
            }
            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => println!("{:?}: compiled to {outfmt:?} ok", fent.path()),
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile (format {outfmt:?}) {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// Try other misc tests.
#[test]
fn can_compile_misc_test_policies() {
    let zpl_dir = get_zpl_dir();
    let temp_dir = TempDir::new("misctest");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list integration-test policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // Must start with "test-"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("test-") {
                        continue;
                    }
                }
            }

            for outfmt in &[OutputFormat::V2] {
                let cb = CompilationBuilder::new(path.clone())
                    .verbose(true)
                    .output_format(*outfmt)
                    .output_directory(&temp_dir.path);
                let mut comp = cb.build();
                match comp.compile() {
                    Ok(_warnings) => {
                        println!("{:?}: compiled ok", fent.path());
                        // Ok now try to dump it.
                        let encoded = std::fs::read(&comp.output_file)
                            .expect("failed to read binary policy file");
                        let encoded_buf = Bytes::from(encoded);
                        match outfmt {
                            OutputFormat::V2 => {
                                dump_v2(&comp.output_file.to_string_lossy(), encoded_buf);
                            }
                            _ => panic!("unsupported output format for dump test"),
                        }
                        println!("{:?}: dumped ok", fent.path());
                    }
                    Err(e) => {
                        println!("error: {}", e);
                        panic!("failed to compile {:?}", fent.path());
                    }
                }
            }
        }
    }
}

// ---- issue #138: `file` trusted services — end-to-end + regression ----

/// Compile `<stem>.zpl` (with its companion `<stem>.zplc`) to a V2 policy and return the inner
/// policy bytes (already unwrapped from the container).
fn compile_policy_bytes(stem: &str, temp: &TempDir) -> Vec<u8> {
    let path = get_zpl_dir().join(format!("{stem}.zpl"));
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    comp.compile()
        .unwrap_or_else(|e| panic!("failed to compile {stem}.zpl: {e}"));
    read_policy_bytes(&comp.output_file)
}

/// Read a compiled V2 policy container file and return the inner policy bytes.
fn read_policy_bytes(container_file: &std::path::Path) -> Vec<u8> {
    let encoded = std::fs::read(container_file).expect("read binary policy");
    let container_rdr = capnp::serialize::read_message(
        &mut Cursor::new(encoded),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode container");
    let container = container_rdr
        .get_root::<policy_capnp::policy_container::Reader>()
        .expect("container root");
    container.get_policy().expect("policy bytes").to_vec()
}

/// Total endpoints across every join-policy Service with the given id, asserting each such
/// Service is `Trusted(expected_api)`.
fn trusted_service_endpoint_count(
    policy: &policy_capnp::policy::Reader,
    id: &str,
    expected_api: &str,
) -> usize {
    let mut count = 0usize;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        for s in provides.iter() {
            if s.get_id().unwrap().to_str().unwrap() == id {
                match s.get_kind().which().unwrap() {
                    policy_capnp::service::kind::Which::Trusted(n) => {
                        assert_eq!(n.unwrap().to_str().unwrap(), expected_api);
                    }
                    _ => panic!("service {id} must be Trusted({expected_api})"),
                }
                count += s.get_endpoints().unwrap().len() as usize;
            }
        }
    }
    count
}

fn decode_records(policy: &policy_capnp::policy::Reader) -> Vec<TrustedService> {
    policy
        .get_trusted_services()
        .unwrap()
        .iter()
        .map(|r| TrustedService::try_from(r).expect("decode trusted service record"))
        .collect()
}

fn mappings(ts: &TrustedService) -> Vec<(&str, &str)> {
    ts.returns_attrs
        .iter()
        .map(|m| (m.service_attr_key.as_str(), m.zpr_attr_spec.as_str()))
        .collect()
}

#[test]
fn test_file_trusted_service_end_to_end() {
    let temp = TempDir::new("file-e2e");
    let pbytes = compile_policy_bytes("test-file", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // --- trustedServices: deterministic order, attrfile + attrs once each ---
    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(ids, vec!["attrfile", "attrs"]);

    // attrfile: expiration 3600, TOML-ordered mappings, empty identity.
    let attrfile = records.iter().find(|r| r.service_id == "attrfile").unwrap();
    assert_eq!(attrfile.expiration_seconds, 3600);
    assert!(attrfile.identity_attrs.is_empty());
    assert_eq!(
        mappings(attrfile),
        vec![("hair_color", "user.hair_color"), ("lazy", "#user.lazy")]
    );

    // attrs: default expiration, no identity attributes.
    let attrs = records.iter().find(|r| r.service_id == "attrs").unwrap();
    assert_eq!(attrs.expiration_seconds, 0);
    assert!(attrs.identity_attrs.is_empty());

    // --- attrfile join Service: Trusted("file"), zero endpoints, selected by cn = vs.zpr ---
    let mut attrfile_svc_found = false;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let svc = match provides
            .iter()
            .find(|s| s.get_id().unwrap().to_str().unwrap() == "attrfile")
        {
            Some(s) => s,
            None => continue,
        };
        attrfile_svc_found = true;

        // The join policy is selected by exactly device.zpr.adapter.cn EQ vs.zpr.
        let match_exprs = jp.get_match().unwrap();
        assert_eq!(match_exprs.len(), 1);
        let e = match_exprs.get(0);
        assert_eq!(
            e.get_key().unwrap().to_str().unwrap(),
            "device.zpr.adapter.cn"
        );
        assert!(matches!(e.get_op().unwrap(), policy_capnp::AttrOp::Eq));
        let vals: Vec<&str> = e
            .get_value()
            .unwrap()
            .iter()
            .map(|v| v.unwrap().to_str().unwrap())
            .collect();
        assert_eq!(vals, vec!["vs.zpr"]);

        // The service itself is Trusted("file") with zero endpoints.
        match svc.get_kind().which().unwrap() {
            policy_capnp::service::kind::Which::Trusted(n) => {
                assert_eq!(n.unwrap().to_str().unwrap(), "file")
            }
            _ => panic!("attrfile must be Trusted(file)"),
        }
        assert_eq!(
            svc.get_endpoints().unwrap().len(),
            0,
            "file service must have zero endpoints"
        );
    }
    assert!(attrfile_svc_found, "attrfile join Service not found");

    // --- no communication policy for the file service ---
    if policy.has_com_policies() {
        for cp in policy.get_com_policies().unwrap().iter() {
            assert_ne!(
                cp.get_service_id().unwrap().to_str().unwrap(),
                "attrfile",
                "file service must have no communication policy"
            );
        }
    }
}

// ---- zipline#23: identity vendors are never pruned ----

#[test]
fn test_identity_vendor_retained_end_to_end() {
    // The zipline#22 configuration: `google` (oidc, vends
    // identity attribute `sub`) plus `happyfile` (file store keyed on
    // user.sub). The single relevant policy statement references only the
    // file store's attribute, so nothing marks `google` used -- the
    // identity-vendor rule must retain it, and BOTH services must appear
    // in the emitted trustedServices.
    let temp = TempDir::new("identity-vendor-e2e");
    let pbytes = compile_policy_bytes("test-oidc-file-interplay", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["google", "happyfile"],
        "both the identity vendor and the file store must be woven"
    );

    // google: retained by the identity-vendor rule, with its OidcConfig intact.
    let google = records.iter().find(|r| r.service_id == "google").unwrap();
    assert_eq!(google.identity_attrs, vec!["sub".to_string()]);
    assert_eq!(
        mappings(google),
        vec![("sub", "user.sub"), ("email", "user.email")]
    );
    let oidc = google.oidc.as_ref().expect("google must carry OidcConfig");
    assert_eq!(oidc.issuer, "https://accounts.google.com");

    // happyfile: retained by the ordinary attribute reference.
    let happyfile = records
        .iter()
        .find(|r| r.service_id == "happyfile")
        .unwrap();
    assert!(happyfile.identity_attrs.is_empty());
    assert_eq!(
        mappings(happyfile),
        vec![("hair_color", "user.hair_color"), ("lazy", "#user.lazy")]
    );
}

/// Compile the zipline#105 retention fixture and return the decoded
/// trustedServices records. The fixture declares three file stores none of
/// whose returned attributes are referenced by ZPL: `addrstore` (vends only
/// `device.zpr_addr`), `hoststore` (vends only `device.hostname{}`) and
/// `colorstore` (vends only `user.color`).
fn retain_fixture_records(tag: &str) -> Vec<TrustedService> {
    let temp = TempDir::new(tag);
    let pbytes = compile_policy_bytes("retain-vs-interpreted", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();
    decode_records(&policy)
}

#[test]
fn test_vs_interpreted_zpr_addr_vendor_retained() {
    // zipline#105: a file store vending only `device.zpr_addr` -- an attribute
    // the visa service reads directly (connection_control's static-address
    // grant), never referenced by ZPL -- must survive pruning.
    let records = retain_fixture_records("retain-zpr-addr");
    let addrstore = records
        .iter()
        .find(|r| r.service_id == "addrstore")
        .expect("addrstore vends device.zpr_addr and must be retained");
    assert!(addrstore.identity_attrs.is_empty());
    assert_eq!(mappings(addrstore), vec![("addr", "device.zpr_addr")]);
}

#[test]
fn test_vs_interpreted_hostname_vendor_retained() {
    // zipline#105: same as above for `device.hostname{}` (multi-valued
    // spelling), the attribute behind the visa service's DNS hosts index.
    let records = retain_fixture_records("retain-hostname");
    let hoststore = records
        .iter()
        .find(|r| r.service_id == "hoststore")
        .expect("hoststore vends device.hostname and must be retained");
    assert!(hoststore.identity_attrs.is_empty());
    assert_eq!(
        mappings(hoststore),
        vec![("hostnames", "device.hostname{}")]
    );
}

#[test]
fn test_unreferenced_ordinary_vendor_still_pruned() {
    // zipline#105 negative case: a store vending only an ordinary
    // unreferenced attribute (`user.color`) is NOT visa-service-interpreted
    // and must still be pruned.
    let records = retain_fixture_records("retain-negative");
    assert!(
        !records.iter().any(|r| r.service_id == "colorstore"),
        "colorstore vends nothing the visa service interprets and must stay pruned"
    );
}

#[test]
fn test_referenced_and_vs_interpreted_vendor_woven_once() {
    // zipline#105: a store that is BOTH referenced by ZPL and a
    // visa-service-interpreted vendor is marked used by the ordinary
    // attribute-reference path before the retain pass runs; the retain pass
    // must skip it, leaving exactly one woven record (and emitting no
    // retention diagnostic for it).
    let temp = TempDir::new("retain-dual");
    let pbytes = compile_policy_bytes("retain-referenced-and-vs", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();
    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["dualstore"],
        "dualstore must be woven exactly once"
    );
}

// ---- deterministic bin2 ordering ----

/// One attribute expression as (key, op, values).
type AttrTuple = (String, String, Vec<String>);

/// Order-preserving structural snapshot of every policy collection that must be
/// deterministically ordered. Bytes can't be compared instead: `created`, `version` and
/// `metadata` are wall-clock derived.
#[derive(Debug, PartialEq)]
struct OrderSnapshot {
    /// (service_id, zpl, client conds, service conds)
    com_policies: Vec<(String, String, Vec<AttrTuple>, Vec<AttrTuple>)>,
    /// (conditions, provided service ids)
    join_policies: Vec<(Vec<AttrTuple>, Vec<String>)>,
    keys: Vec<String>,
    /// (link_id, attributes)
    topology: Vec<(String, Vec<AttrTuple>)>,
    trusted_services: Vec<String>,
}

fn attr_tuples(list: capnp::struct_list::Reader<policy_capnp::attr_expr::Owned>) -> Vec<AttrTuple> {
    list.iter()
        .map(|e| {
            (
                e.get_key().unwrap().to_str().unwrap().to_string(),
                format!("{:?}", e.get_op().unwrap()),
                e.get_value()
                    .unwrap()
                    .iter()
                    .map(|v| v.unwrap().to_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

/// The same ordering key `JPKey` uses: op lowercased, values sorted, tuples key-sorted.
fn jp_sort_key(conds: &[AttrTuple]) -> Vec<AttrTuple> {
    let mut k: Vec<AttrTuple> = conds
        .iter()
        .map(|(key, op, vals)| {
            let mut vals = vals.clone();
            vals.sort();
            (key.clone(), op.to_lowercase(), vals)
        })
        .collect();
    k.sort();
    k
}

fn snapshot(pbytes: &[u8]) -> OrderSnapshot {
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode policy");
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let com_policies = policy
        .get_com_policies()
        .unwrap()
        .iter()
        .map(|cp| {
            (
                cp.get_service_id().unwrap().to_str().unwrap().to_string(),
                cp.get_zpl().unwrap().to_str().unwrap().to_string(),
                attr_tuples(cp.get_client_conds().unwrap()),
                attr_tuples(cp.get_service_conds().unwrap()),
            )
        })
        .collect();

    let join_policies = policy
        .get_join_policies()
        .unwrap()
        .iter()
        .map(|jp| {
            let provides = jp
                .get_provides()
                .map(|ps| {
                    ps.iter()
                        .map(|s| s.get_id().unwrap().to_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default();
            (attr_tuples(jp.get_match().unwrap()), provides)
        })
        .collect();

    let keys = policy
        .get_keys()
        .unwrap()
        .iter()
        .map(|k| k.get_id().unwrap().to_str().unwrap().to_string())
        .collect();

    let topology = policy
        .get_topology()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p.get_link_id().unwrap().to_str().unwrap().to_string(),
                attr_tuples(p.get_attrs().unwrap()),
            )
        })
        .collect();

    let trusted_services = policy
        .get_trusted_services()
        .unwrap()
        .iter()
        .map(|ts| ts.get_service_id().unwrap().to_str().unwrap().to_string())
        .collect();

    OrderSnapshot {
        com_policies,
        join_policies,
        keys,
        topology,
        trusted_services,
    }
}

fn assert_sorted<T: Ord + std::fmt::Debug + Clone>(what: &str, items: &[T]) {
    let mut sorted = items.to_vec();
    sorted.sort();
    assert_eq!(sorted, items, "{what} must be sorted");
}

#[test]
fn test_bin2_ordering_is_deterministic() {
    // Distinct hints: TempDir paths are (hint, pid, seconds), so same-hint dirs alias.
    let temp_a = TempDir::new("ordering-a");
    let temp_b = TempDir::new("ordering-b");
    let snap_a = snapshot(&compile_policy_bytes("test-ordering", &temp_a));
    let snap_b = snapshot(&compile_policy_bytes("test-ordering", &temp_b));
    assert_eq!(
        snap_a, snap_b,
        "recompiling the same input must not reorder"
    );

    let snap = snap_a;

    // Com policies: grouped by service_id ascending, attribute lists key-sorted.
    assert_sorted(
        "com policy service ids",
        &snap
            .com_policies
            .iter()
            .map(|(id, ..)| id.clone())
            .collect::<Vec<_>>(),
    );
    for (id, _zpl, cli, svc) in &snap.com_policies {
        assert_sorted(
            &format!("{id} client cond keys"),
            &cli.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
        assert_sorted(
            &format!("{id} service cond keys"),
            &svc.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
    }

    // Within a service, ZPL source order survives: `never` first, then the allows.
    let db1: Vec<&str> = snap
        .com_policies
        .iter()
        .filter(|(id, ..)| id == "database#1")
        .map(|(_, zpl, ..)| zpl.as_str())
        .collect();
    assert_eq!(
        db1,
        vec![
            "(line 9) never allow color:red employees to access classified databases",
            "(line 10) allow lazy, color:green employees to access classified databases on tint:sales devices",
            "(line 11) allow clearance:classified government users to access classified services",
        ]
    );

    // Join policies: outer order follows the full structured condition key; inner lists
    // key-sorted; provides sorted by service id.
    assert_sorted(
        "join policy condition keys",
        &snap
            .join_policies
            .iter()
            .map(|(conds, _)| jp_sort_key(conds))
            .collect::<Vec<_>>(),
    );
    for (conds, provides) in &snap.join_policies {
        assert_sorted(
            "join condition keys",
            &conds.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
        assert_sorted("join policy provides", provides);
    }

    // Keys, topology (including per-link attributes) and trusted services.
    assert_sorted("bootstrap keys", &snap.keys);
    assert_sorted(
        "topology link ids",
        &snap
            .topology
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>(),
    );
    for (link_id, attrs) in &snap.topology {
        assert_sorted(
            &format!("{link_id} attribute keys"),
            &attrs.iter().map(|(k, ..)| k.clone()).collect::<Vec<_>>(),
        );
    }
    assert_sorted("trusted services", &snap.trusted_services);

    // Sanity: the fixture actually exercises every collection.
    assert!(
        snap.keys.len() >= 2,
        "fixture needs multiple bootstrap keys"
    );
    assert!(snap.topology.len() >= 2, "fixture needs multiple links");
    assert!(
        snap.trusted_services.len() >= 2,
        "fixture needs multiple trusted services"
    );
    assert_eq!(
        db1.len(),
        3,
        "fixture needs a suffixed service with 3 rules"
    );
}

#[test]
fn test_tag_conditions_one_key_per_tag() {
    // Each tag compiles to its own `<domain>.zpr.tag.<name>` key with a valueless HAS
    // (presence check). Multiple tags on one statement must not clobber each other.
    //
    // Previously we mapped tags to <domain>.zpr.tag so tags in the same domain
    // clobbered each other.
    let temp = TempDir::new("tag-encoding");
    let pbytes = compile_policy_bytes("test-tag", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let mut allow_keys: Option<Vec<String>> = None;
    let mut deny_keys: Option<Vec<String>> = None;
    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "database" {
            continue;
        }
        let mut keys = Vec::new();
        for cond in cp.get_client_conds().unwrap().iter() {
            let key = cond.get_key().unwrap().to_str().unwrap().to_string();
            assert!(
                matches!(cond.get_op().unwrap(), policy_capnp::AttrOp::Has),
                "tag condition {key} must be HAS"
            );
            assert_eq!(
                cond.get_value().unwrap().len(),
                0,
                "tag condition {key} must be valueless (presence check)"
            );
            keys.push(key);
        }
        keys.sort();
        if cp.get_allow() {
            allow_keys = Some(keys);
        } else {
            deny_keys = Some(keys);
        }
    }

    // The allow statement carries the injected `has user.zpr.authority` presence
    // marker (#144); the never statement must NOT (a marker would narrow the
    // deny).
    assert_eq!(
        allow_keys.expect("allow policy for database not found"),
        vec![
            "user.zpr.authority",
            "user.zpr.tag.nerd",
            "user.zpr.tag.redhead"
        ]
    );
    assert_eq!(
        deny_keys.expect("never policy for database not found"),
        vec!["user.zpr.tag.baldy", "user.zpr.tag.stud"]
    );
}

#[test]
fn test_link_conditions_end_to_end() {
    // An "over <link-clause>" constrains the links of the communication path.
    // The compiler records those constraints in `CPolicy.linkConds`; enforcement
    // is the visa service's job and is deliberately out of scope here.
    let temp = TempDir::new("link-over");
    let pbytes = compile_policy_bytes("test-link-over", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // Collect (client-condition keys, link-condition tuples) per database policy.
    let mut allow_with_links: Option<Vec<(String, Vec<String>)>> = None;
    let mut deny_with_links: Option<Vec<(String, Vec<String>)>> = None;
    let mut saw_policy_without_links = false;

    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "database" {
            continue;
        }
        let mut link_conds = Vec::new();
        for cond in cp.get_link_conds().unwrap().iter() {
            let key = cond.get_key().unwrap().to_str().unwrap().to_string();
            let vals: Vec<String> = cond
                .get_value()
                .unwrap()
                .iter()
                .map(|v| v.unwrap().to_str().unwrap().to_string())
                .collect();
            link_conds.push((key, vals));
        }
        link_conds.sort();

        let cli_keys: Vec<String> = cp
            .get_client_conds()
            .unwrap()
            .iter()
            .map(|c| c.get_key().unwrap().to_str().unwrap().to_string())
            .collect();

        if link_conds.is_empty() {
            // This is the "nerd" statement, which has no over clause.
            assert!(
                cli_keys.iter().any(|k| k.contains("nerd")),
                "unexpected policy with no link conditions: {cli_keys:?}"
            );
            saw_policy_without_links = true;
        } else if cp.get_allow() {
            allow_with_links = Some(link_conds);
        } else {
            deny_with_links = Some(link_conds);
        }
    }

    // "over secure, location:usa links" -> a valueless tag plus a key/value pair,
    // both in the link domain.
    let allow_conds = allow_with_links.expect("allow policy with link conditions not found");
    assert_eq!(
        allow_conds,
        vec![
            ("link.location".to_string(), vec!["usa".to_string()]),
            ("link.zpr.tag.secure".to_string(), vec![]),
        ]
    );

    // "never allow ... over foreign links" must carry its link condition too.
    let deny_conds = deny_with_links.expect("never policy with link conditions not found");
    assert_eq!(
        deny_conds,
        vec![("link.zpr.tag.foreign".to_string(), vec![])]
    );

    assert!(
        saw_policy_without_links,
        "expected a policy with no over clause to have empty linkConds"
    );

    // Every emitted link condition must actually be satisfiable by a link in the
    // compiled topology. This is the property that matters: the ZPL side and the
    // ZPLC side have to agree on the attribute encoding, otherwise a `never allow`
    // with an over clause would fail open once the visa service enforces link rules.
    let mut topo_keys: Vec<String> = Vec::new();
    for peering in policy.get_topology().unwrap().iter() {
        for attr in peering.get_attrs().unwrap().iter() {
            topo_keys.push(attr.get_key().unwrap().to_str().unwrap().to_string());
        }
    }
    topo_keys.sort();
    topo_keys.dedup();

    // The tag on the link (`["#secure", ""]` in the zplc) must encode identically to
    // the tag written in ZPL (`over secure links`).
    assert!(
        topo_keys.contains(&"link.zpr.tag.secure".to_string()),
        "configured link tag not encoded as link.zpr.tag.secure: {topo_keys:?}"
    );
    assert!(
        topo_keys.contains(&"link.zpr.tag.foreign".to_string()),
        "configured link tag not encoded as link.zpr.tag.foreign: {topo_keys:?}"
    );
    assert!(
        topo_keys.contains(&"link.location".to_string()),
        "configured link key/value attribute missing: {topo_keys:?}"
    );

    for (key, _) in allow_conds.iter().chain(deny_conds.iter()) {
        assert!(
            topo_keys.contains(key),
            "link condition {key} is satisfied by no configured link (topology keys: {topo_keys:?})"
        );
    }

    // The VisaService admin policy is built on a separate path in the weaver
    // (visa_services_to_services). Its over clause must be preserved too:
    // "allow redhead users to access VisaService over secure links" must not
    // grant admin access over arbitrary links.
    let mut admin_link_conds: Option<Vec<(String, Vec<String>)>> = None;
    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "/zpr/visaservice/admin" {
            continue;
        }
        let mut link_conds = Vec::new();
        for cond in cp.get_link_conds().unwrap().iter() {
            let key = cond.get_key().unwrap().to_str().unwrap().to_string();
            let vals: Vec<String> = cond
                .get_value()
                .unwrap()
                .iter()
                .map(|v| v.unwrap().to_str().unwrap().to_string())
                .collect();
            link_conds.push((key, vals));
        }
        link_conds.sort();
        admin_link_conds = Some(link_conds);
    }
    assert_eq!(
        admin_link_conds.expect("VisaService admin policy not found"),
        vec![("link.zpr.tag.secure".to_string(), vec![])],
        "over clause dropped from the VisaService admin policy"
    );
}

#[test]
fn test_over_clause_with_unconfigured_attribute_fails_to_compile() {
    // ZPL and ZPLC are always compiled together, so a link attribute that appears on no
    // configured link means the author wrote a statement that can never match. Fail loudly.
    // Named "bad-" rather than "test-" so the bulk must-compile sweeps skip it.
    let temp = TempDir::new("link-over-bad");
    let path = get_zpl_dir().join("bad-link-over-unsatisfiable.zpl");
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    let err = comp
        .compile()
        .expect_err("over clause naming an unconfigured link attribute must not compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not present on any configured link"),
        "unexpected error: {msg}"
    );
    assert!(
        msg.contains("nosuchtag"),
        "error should name the offending attribute: {msg}"
    );
}

#[test]
fn test_over_clause_with_unconfigured_value_warns_but_compiles() {
    // Distinct from the case above: the link attribute `location` IS configured, but no
    // link carries the value `use` (the configured values are `usa` and `eu`). That is a
    // likely typo, so it is reported -- but link values are topology data a later config
    // edit may legitimately introduce, so it must not fail the compile.
    let temp = TempDir::new("link-over-unknown-value");
    let path = get_zpl_dir().join("test-link-over-unknown-value.zpl");
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    comp.compile()
        .expect("an over clause with an unknown value must warn, not fail");

    // The warning text itself is asserted in weaver::test::test_link_condition_unknown_value_warns;
    // `compile()` returns unit on success, so it cannot be inspected from here, and --werror
    // would trip on the unrelated "no policy granting admin access to VisaService" warning first.
}

// ---- zipline#6: `api = "oidc"` trusted services — end-to-end + error paths ----

/// Compile `<stem>.zpl` (with its companion `<stem>.zplc`) expecting a compilation
/// error; returns the error text.
fn compile_expect_err(stem: &str, temp: &TempDir) -> String {
    let path = get_zpl_dir().join(format!("{stem}.zpl"));
    let cb = CompilationBuilder::new(path)
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path);
    let mut comp = cb.build();
    comp.compile()
        .expect_err(&format!("{stem}.zpl must fail to compile"))
        .to_string()
}

#[test]
fn test_oidc_trusted_service_end_to_end() {
    let temp = TempDir::new("oidc-e2e");
    let pbytes = compile_policy_bytes("test-oidc", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // --- exactly one TrustedService record: google, with the OidcConfig ---
    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(ids, vec!["google"]);

    let google = &records[0];
    assert_eq!(google.expiration_seconds, 43200);
    assert_eq!(google.identity_attrs, vec!["sub".to_string()]);
    // TOML declaration order preserved.
    assert_eq!(
        mappings(google),
        vec![
            ("sub", "user.oidc-subject"),
            ("email", "user.email"),
            ("hd", "user.domain"),
        ]
    );

    let oidc = google.oidc.as_ref().expect("google must carry OidcConfig");
    assert_eq!(oidc.issuer, "https://accounts.google.com");
    assert_eq!(oidc.jwks_uri, "https://www.googleapis.com/oauth2/v3/certs");
    assert_eq!(
        oidc.client_id,
        "1234567890-abcdef.apps.googleusercontent.com"
    );
    assert_eq!(oidc.client_secret, None, "fixture omits client_secret");
    assert_eq!(oidc.scopes, vec!["openid", "email", "profile"]);
    assert_eq!(oidc.allowed_domains, vec!["example.com", "eu.example.com"]);
    assert_eq!(oidc.max_auth_age_seconds, 86400);
    assert!(!oidc.allow_offline_access);
    assert_eq!(
        oidc.jwks_proxy_service.as_deref(),
        Some("google-jwks-proxy")
    );

    // seed_jwks embedded verbatim: a JWKS document with two keys.
    let seed: serde_json::Value =
        serde_json::from_str(&oidc.seed_jwks).expect("seed_jwks must be valid JSON");
    assert_eq!(
        seed["keys"].as_array().expect("top-level keys array").len(),
        2,
        "seed JWKS must have 2 keys"
    );

    // --- the woven JWKS-proxy rule: a client policy on google-jwks-proxy
    // selected by exactly device.zpr.adapter.cn EQ vs.zpr ---
    let mut proxy_rule_found = false;
    for cp in policy.get_com_policies().unwrap().iter() {
        if cp.get_service_id().unwrap().to_str().unwrap() != "google-jwks-proxy" {
            continue;
        }
        proxy_rule_found = true;
        let conds = cp.get_client_conds().unwrap();
        assert_eq!(conds.len(), 1, "proxy rule must have one client condition");
        let e = conds.get(0);
        assert_eq!(
            e.get_key().unwrap().to_str().unwrap(),
            "device.zpr.adapter.cn"
        );
        assert!(matches!(e.get_op().unwrap(), policy_capnp::AttrOp::Eq));
        let vals: Vec<&str> = e
            .get_value()
            .unwrap()
            .iter()
            .map(|v| v.unwrap().to_str().unwrap())
            .collect();
        assert_eq!(vals, vec!["vs.zpr"]);
    }
    assert!(
        proxy_rule_found,
        "woven visa-service rule targeting google-jwks-proxy not found"
    );

    // --- google join Service: Trusted("oidc") with zero endpoints (file-style early-out) ---
    let mut google_svc_found = false;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let svc = match provides
            .iter()
            .find(|s| s.get_id().unwrap().to_str().unwrap() == "google")
        {
            Some(s) => s,
            None => continue,
        };
        google_svc_found = true;
        match svc.get_kind().which().unwrap() {
            policy_capnp::service::kind::Which::Trusted(n) => {
                assert_eq!(n.unwrap().to_str().unwrap(), "oidc")
            }
            _ => panic!("google must be Trusted(oidc)"),
        }
        assert_eq!(
            svc.get_endpoints().unwrap().len(),
            0,
            "oidc service must have zero endpoints"
        );
    }
    assert!(google_svc_found, "google join Service not found");
}

#[test]
fn test_oidc_stray_services_block_rejected() {
    let temp = TempDir::new("oidc-stray-svc");
    let msg = compile_expect_err("bad-oidc-services-block", &temp);
    assert!(
        msg.contains(
            "trusted_service google: api=\"oidc\" has no on-net service; remove [services.google-vs]"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_oidc_missing_proxy_service_rejected() {
    let temp = TempDir::new("oidc-missing-proxy");
    let msg = compile_expect_err("bad-oidc-missing-proxy-service", &temp);
    assert!(
        msg.contains("trusted_service google: service \"nope\" is not declared in [services]"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_oidc_offline_access_without_ceiling_rejected() {
    // zipline#41: allow_offline_access without a session ceiling must fail.
    let temp = TempDir::new("oidc-offline-no-ceiling");
    let msg = compile_expect_err("bad-oidc-offline-no-ceiling", &temp);
    assert!(
        msg.contains(
            "trusted_service google: allow_offline_access requires max_auth_age_seconds (the session ceiling)"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_oidc_ceiling_below_expiration_rejected() {
    // zipline#41: a non-zero ceiling below expiration_seconds must fail.
    let temp = TempDir::new("oidc-ceiling-below-expiration");
    let msg = compile_expect_err("bad-oidc-ceiling-below-expiration", &temp);
    assert!(
        msg.contains("trusted_service google: max_auth_age_seconds must be >= expiration_seconds"),
        "unexpected error: {msg}"
    );
}

// ---- zipline#76: `api = "zpr-attr/1"` attribute services — end-to-end + error paths ----

#[test]
fn test_attr_query_end_to_end() {
    // The oidc-file-interplay pattern with the file store replaced by a
    // zpr-attr/1 attribute service: `google` (oidc, vends identity attribute
    // `sub`) is retained by the identity-vendor rule; `zipline` is retained by
    // the ordinary attribute reference and carries an AttrQueryConfig.
    let temp = TempDir::new("attr-query-e2e");
    let pbytes = compile_policy_bytes("test-attr-query", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    assert!(
        policy.has_trusted_services(),
        "policy must have trustedServices"
    );
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["google", "zipline"],
        "both the identity vendor and the attribute service must be woven"
    );

    // google: retained by the identity-vendor rule, with its OidcConfig intact.
    let google = records.iter().find(|r| r.service_id == "google").unwrap();
    assert_eq!(google.identity_attrs, vec!["sub".to_string()]);
    assert!(google.attr_query.is_none());

    // zipline: the attribute service record.
    let zipline = records.iter().find(|r| r.service_id == "zipline").unwrap();
    assert_eq!(zipline.expiration_seconds, 3600);
    assert!(
        zipline.identity_attrs.is_empty(),
        "an attribute service declares no identity attributes"
    );
    assert!(zipline.oidc.is_none());
    assert_eq!(
        mappings(zipline),
        vec![
            ("dept", "user.dept"),
            ("roles", "user.role{}"),
            ("contractor", "#user.contractor"),
        ]
    );
    let aq = zipline
        .attr_query
        .as_ref()
        .expect("zipline must carry AttrQueryConfig");
    assert_eq!(
        aq.url, "https://attrs.zipline.example/tenant-7",
        "trailing slash must be stripped"
    );
    assert_eq!(aq.timeout_seconds, 10);
    // The CA pin is the embedded PEM contents of test-data/ca-cert.pem, not the path.
    let pem = aq.ca_cert_pem.as_ref().expect("CA pin embedded");
    assert!(
        pem.contains("-----BEGIN CERTIFICATE-----"),
        "embedded pin must be PEM contents"
    );
    let expected_pem = std::fs::read_to_string(get_zpl_dir().join("ca-cert.pem")).unwrap();
    assert_eq!(pem, &expected_pem, "PEM embedded verbatim");

    // zipline join Service: Trusted("zpr-attr/1") with zero endpoints
    // (file-style shape: the VS itself is the provider).
    assert_eq!(
        trusted_service_endpoint_count(&policy, "zipline", "zpr-attr/1"),
        0,
        "attribute service must have zero endpoints"
    );
}

#[test]
fn test_attr_query_unreferenced_pruned() {
    // No policy statement references the attribute service's attributes and it
    // vends no identity attributes, so the weaver must prune it: no
    // trustedServices record and no join Service.
    let temp = TempDir::new("attr-query-pruned");
    let pbytes = compile_policy_bytes("test-attr-query-pruned", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let records = decode_records(&policy);
    assert!(
        !records.iter().any(|r| r.service_id == "zipline"),
        "unreferenced attribute service must be pruned, got records: {:?}",
        records.iter().map(|r| &r.service_id).collect::<Vec<_>>()
    );
    for jp in policy.get_join_policies().unwrap().iter() {
        if let Ok(provides) = jp.get_provides() {
            assert!(
                !provides
                    .iter()
                    .any(|s| s.get_id().unwrap().to_str().unwrap() == "zipline"),
                "pruned attribute service must not appear as a join Service"
            );
        }
    }
}

#[test]
fn test_attr_query_http_url_rejected() {
    let temp = TempDir::new("attr-query-http-url");
    let msg = compile_expect_err("bad-attr-query-http-url", &temp);
    assert!(
        msg.contains("trusted_service zipline: url must be an https URL without query or fragment"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_attr_query_identity_attrs_rejected() {
    let temp = TempDir::new("attr-query-identity-attrs");
    let msg = compile_expect_err("bad-attr-query-identity-attrs", &temp);
    assert!(
        msg.contains(
            "trusted_service zipline with api \"zpr-attr/1\" does not allow property 'identity_attributes'"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_attr_query_service_reserved_rejected() {
    let temp = TempDir::new("attr-query-service-reserved");
    let msg = compile_expect_err("bad-attr-query-service-reserved", &temp);
    assert!(
        msg.contains("trusted_service zipline: \"service\" is reserved for api=\"zpr-attr/1\""),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_attr_query_truncated_ca_pem_rejected() {
    // (PR #8 review) A ca_cert_path whose file carries the CERTIFICATE marker
    // but a truncated body must fail compilation, not break the visa service's
    // trust store at runtime.
    let temp = TempDir::new("attr-query-bad-ca-pem");
    let msg = compile_expect_err("bad-attr-query-ca-pem", &temp);
    assert!(
        msg.contains("no valid certificate"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_oidc_proxy_provider_trusted_service_dependency_woven() {
    // (zipline#6 review) The JWKS proxy's provider attributes may resolve through
    // a trusted service used nowhere else (`attrfile` via device.color). That
    // dependency must be discovered before the trusted services are woven, or
    // `attrfile` silently gets no TrustedService record or connect entry.
    let temp = TempDir::new("oidc-proxy-provider-ts");
    let pbytes = compile_policy_bytes("test-oidc-proxy-provider-ts", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    // Both trusted services must have metadata records (sorted weave order).
    let records = decode_records(&policy);
    let ids: Vec<&str> = records.iter().map(|r| r.service_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["attrfile", "google"],
        "trusted service discovered only via the proxy provider must still be woven"
    );

    // And attrfile must appear as a Trusted("file") join Service.
    let mut attrfile_found = false;
    for jp in policy.get_join_policies().unwrap().iter() {
        let provides = match jp.get_provides() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if provides
            .iter()
            .any(|s| s.get_id().unwrap().to_str().unwrap() == "attrfile")
        {
            attrfile_found = true;
        }
    }
    assert!(attrfile_found, "attrfile join Service not found");
}

/// Build and compile an oidc fixture in a temp dir whose `[services]` proxy id is
/// `svc_id`; returns the compilation error text (panics if it compiles).
fn compile_oidc_proxy_id_expect_err(tag: &str, svc_id: &str) -> String {
    let temp = TempDir::new(tag);
    let zpl_path = temp.path.join("fixture.zpl");
    std::fs::write(
        &zpl_path,
        "define Webby as a service.\nallow domain:'example.com' users to access Webby.\n",
    )
    .unwrap();
    std::fs::write(
        temp.path.join("fixture.zplc"),
        format!(
            r#"
[nodes.n0]
provider = [["device.zpr.adapter.cn", "node.zpr.org"]]
zpr_address = "fd5a:5052:90de::1"

[trusted_services.google]
api             = "oidc"
issuer          = "https://accounts.google.com"
jwks_uri        = "https://www.googleapis.com/oauth2/v3/certs"
client_id       = "1234567890-abcdef.apps.googleusercontent.com"
allowed_domains = ["example.com"]
expiration_seconds = 43200
returns_attributes = ["sub -> user.oidc-subject", "hd -> user.domain"]
identity_attributes = ["sub"]
service = "{svc_id}"

[protocols.http]
l4protocol = "TCP"
port = 80

[protocols.tcp]
l4protocol = "TCP"
port = 3128

[services."{svc_id}"]
protocol = "tcp"
port = 3128
provider = [["device.zpr.adapter.cn", "proxy1.zpr"]]

[services.Webby]
protocol = "http"
port = 80
provider = [["device.zpr.adapter.cn", "webby.zpr.org"]]
"#
        ),
    )
    .unwrap();

    let out = TempDir::new(&format!("{tag}-out"));
    let cb = CompilationBuilder::new(zpl_path)
        .output_format(OutputFormat::V2)
        .output_directory(&out.path);
    let mut comp = cb.build();
    comp.compile()
        .expect_err(&format!("proxy id {svc_id:?} must fail to compile"))
        .to_string()
}

#[test]
fn test_oidc_proxy_id_with_spaces_rejected() {
    // (zipline#6 review) set_connects/set_policies canonicalize service ids
    // (spaces -> underscores) but OidcConfig.jwks_proxy_service stored the raw
    // name, so a quoted id with spaces made the VS look up a nonexistent
    // service. Reject ids that would need mangling.
    let msg = compile_oidc_proxy_id_expect_err("oidc-proxy-spaces", "google jwks proxy");
    assert!(
        msg.contains(
            "trusted_service google: service \"google jwks proxy\" contains spaces; \
             the policy stores canonicalized service ids (spaces become underscores), \
             so the stored proxy id would never match -- rename the [services] entry"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_oidc_proxy_id_colliding_with_trusted_service_rejected() {
    // (zipline#6 review) service = "google" with [services.google] previously
    // failed deep in add_trusted_service with a confusing "duplicate trusted
    // service" error. The collision must be diagnosed explicitly.
    let msg = compile_oidc_proxy_id_expect_err("oidc-proxy-collision", "google");
    assert!(
        msg.contains(
            "trusted_service google: service \"google\" collides with the id of a \
             trusted service; the JWKS proxy must use a distinct [services] id"
        ),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_seed_jwks_not_a_jwks_document_rejected() {
    // A seed_jwks file that is valid JSON but has no top-level `keys` array is
    // not a JWKS document. Built in a temp dir so no bad fixture is swept.
    let temp = TempDir::new("oidc-bad-seed");
    let zpl_path = temp.path.join("bad-seed.zpl");
    let zplc_path = temp.path.join("bad-seed.zplc");
    std::fs::write(
        &zpl_path,
        "define Webby as a service.\nallow domain:'example.com' users to access Webby.\n",
    )
    .unwrap();
    std::fs::write(temp.path.join("not-a-jwks.json"), "{\"nokeys\": true}\n").unwrap();
    std::fs::write(
        &zplc_path,
        r#"
[nodes.n0]
provider = [["device.zpr.adapter.cn", "node.zpr.org"]]
zpr_address = "fd5a:5052:90de::1"

[trusted_services.google]
api             = "oidc"
issuer          = "https://accounts.google.com"
jwks_uri        = "https://www.googleapis.com/oauth2/v3/certs"
client_id       = "1234567890-abcdef.apps.googleusercontent.com"
allowed_domains = ["example.com"]
seed_jwks       = "not-a-jwks.json"
expiration_seconds = 43200
returns_attributes = ["sub -> user.oidc-subject", "hd -> user.domain"]
identity_attributes = ["sub"]

[protocols.http]
l4protocol = "TCP"
port = 80

[services.Webby]
protocol = "http"
port = 80
provider = [["device.zpr.adapter.cn", "webby.zpr.org"]]
"#,
    )
    .unwrap();

    let out = TempDir::new("oidc-bad-seed-out");
    let cb = CompilationBuilder::new(zpl_path)
        .output_format(OutputFormat::V2)
        .output_directory(&out.path);
    let mut comp = cb.build();
    let msg = comp
        .compile()
        .expect_err("a seed_jwks without a top-level keys array must not compile")
        .to_string();
    assert!(
        msg.contains(
            "trusted_service google: seed_jwks \"not-a-jwks.json\" is not a JWKS document"
        ),
        "unexpected error: {msg}"
    );
}

// ---- zipline#109: authored `zpr.addr` provider pins are rejected ----
//
// Static adapter addresses come from a trusted service vending `device.zpr_addr`
// (umbrella zipline#106); the compiler rejects `["zpr.addr", ...]` in every
// provider list that routes through `vec_to_attributes`. A node's `zpr_address`
// is NOT a provider pin and still emits the `zpr.addr` join condition (guarded
// below). Note: `visa_service.admin_attrs` is not a rejection site because the
// current compiler does not parse it (`parse_visa_service` accepts only
// `dock_node`), so no fixture can route a pin through it.

/// Assert the zipline#109 rejection error: it must name `zpr.addr` and point
/// the author at a `device.zpr_addr` grant.
fn assert_zpr_addr_pin_rejected(msg: &str) {
    assert!(
        msg.contains("zpr.addr") && msg.contains("device.zpr_addr"),
        "error must reject the pin and name device.zpr_addr: {msg}"
    );
}

#[test]
fn test_zpr_addr_pin_in_service_provider_rejected() {
    let temp = TempDir::new("zpr-addr-service");
    let msg = compile_expect_err("bad-zpr-addr-service", &temp);
    assert_zpr_addr_pin_rejected(&msg);
}

#[test]
fn test_zpr_addr_pin_in_node_provider_rejected() {
    let temp = TempDir::new("zpr-addr-node");
    let msg = compile_expect_err("bad-zpr-addr-node", &temp);
    assert_zpr_addr_pin_rejected(&msg);
}

#[test]
fn test_zpr_addr_pin_in_oidc_proxy_provider_rejected() {
    let temp = TempDir::new("zpr-addr-oidc-proxy");
    let msg = compile_expect_err("bad-zpr-addr-oidc-proxy", &temp);
    assert_zpr_addr_pin_rejected(&msg);
}

#[test]
fn test_zpr_addr_pin_in_unreferenced_service_provider_rejected() {
    // Review round 1 (zipline#109): the documented contract is a compile error
    // for an authored pin ANYWHERE in a .zplc. A service the ZPL never
    // references is not selected by weaving, so a weaving-time check misses it;
    // the rejection must be eager, at config parse time.
    let temp = TempDir::new("zpr-addr-unref-service");
    let msg = compile_expect_err("bad-zpr-addr-unref-service", &temp);
    assert_zpr_addr_pin_rejected(&msg);
}

#[test]
fn test_node_zpr_address_still_emits_join_condition() {
    // Regression guard: a node's `zpr_address` is topology, not an authored
    // provider pin. It must still reach the policy as a `zpr.addr` join
    // condition after the pin rejection (zipline#109).
    let temp = TempDir::new("node-zpr-addr");
    let pbytes = compile_policy_bytes("test-file", &temp);
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes.as_slice()),
        capnp::message::ReaderOptions::new(),
    )
    .unwrap();
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();

    let mut node_addr_condition_found = false;
    for jp in policy.get_join_policies().unwrap().iter() {
        for e in jp.get_match().unwrap().iter() {
            if e.get_key().unwrap().to_str().unwrap() == "zpr.addr" {
                let vals: Vec<&str> = e
                    .get_value()
                    .unwrap()
                    .iter()
                    .map(|v| v.unwrap().to_str().unwrap())
                    .collect();
                assert_eq!(vals, vec!["fd5a:5052:90de::1"]);
                node_addr_condition_found = true;
            }
        }
    }
    assert!(
        node_addr_condition_found,
        "node zpr_address must still emit a zpr.addr join condition"
    );
}

// ---- zipline#185: two required values of a multi-valued attribute ----

/// Compile ZPL source text against `test-data/multi-valued-tags.zplc`. The source
/// is written to a temp directory so each case needs no fixture file of its own.
/// Returns the inner policy bytes, or the compilation error text.
fn compile_mv_tags(name: &str, zpl: &str, temp: &TempDir) -> Result<Vec<u8>, String> {
    let zpl_path = temp.path.join(format!("{name}.zpl"));
    std::fs::write(&zpl_path, zpl).expect("write zpl source");
    let mut comp = CompilationBuilder::new(zpl_path)
        .config(&get_zpl_dir().join("multi-valued-tags.zplc"))
        .output_format(OutputFormat::V2)
        .output_directory(&temp.path)
        .build();
    comp.compile().map_err(|e| e.to_string())?;
    Ok(read_policy_bytes(&comp.output_file))
}

/// The `device.tags` values (sorted) in a list of attribute expressions; empty if absent.
fn device_tags(conds: &[AttrTuple]) -> Vec<String> {
    let mut vals: Vec<String> = conds
        .iter()
        .filter(|(k, _, _)| k == "device.tags")
        .flat_map(|(_, _, v)| v.clone())
        .collect();
    vals.sort();
    vals
}

/// What the one tag-conditioned allow statement requires, as
/// (client `device.tags`, host `device.tags`). The host side is the union of the
/// join condition for the statement's service and any service condition on the
/// statement, since either may carry it: an `on` clause compiles to a derived
/// service *and* a service condition, the set form to the join condition alone.
fn tag_requirements(pbytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode policy");
    let policy = rdr.get_root::<policy_capnp::policy::Reader>().unwrap();
    let mut found = None;
    for cp in policy.get_com_policies().unwrap().iter() {
        let client = attr_tuples(cp.get_client_conds().unwrap());
        if !cp.get_allow() || device_tags(&client).is_empty() {
            continue;
        }
        assert!(found.is_none(), "expected one tag-conditioned allow policy");
        let svc_id = cp.get_service_id().unwrap().to_str().unwrap().to_string();
        let mut host = attr_tuples(cp.get_service_conds().unwrap());
        for jp in policy.get_join_policies().unwrap().iter() {
            let provides_svc = jp
                .get_provides()
                .unwrap()
                .iter()
                .any(|s| s.get_id().unwrap().to_str().unwrap() == svc_id);
            if provides_svc {
                host.extend(attr_tuples(jp.get_match().unwrap()));
            }
        }
        let mut host_tags = device_tags(&host);
        host_tags.dedup();
        found = Some((device_tags(&client), host_tags));
    }
    found.expect("no tag-conditioned allow policy")
}

/// `ssh` hosts are servers; shared first line of every #185 case.
const MV_SSH: &str = "define ssh as a service with device.tags:'server'.\n";

/// Set form: phones reach ssh on hosts tagged both server and media.
const MV_SERVER_SET: &str = "define ssh as a service with device.tags:{server,media}.\n\
     allow device.tags:'phone' devices to access ssh.\n";

/// Set form: devices tagged both laptop and work reach ssh.
const MV_CLIENT_SET: &str = "define ssh as a service with device.tags:'server'.\n\
     allow device.tags:{laptop,work} devices to access ssh.\n";

#[test]
fn test_multi_valued_requirements_combine() {
    // zipline#185: each statement requires two values of the multi-valued
    // `device.tags`. Each must compile, and to the same conditions as the
    // equivalent set form.
    let cases: [(&str, &str, &str); 5] = [
        (
            "on-attr",
            "allow device.tags:'phone' devices to access ssh on device.tags:'media' devices.\n",
            MV_SERVER_SET,
        ),
        (
            "on-class",
            "define media as a device with device.tags:'media'.\n\
             allow device.tags:'phone' devices to access ssh on media.\n",
            MV_SERVER_SET,
        ),
        (
            "class-attr",
            "define laptop as a device with device.tags:'laptop'.\n\
             allow device.tags:'work' laptops to access ssh.\n",
            MV_CLIENT_SET,
        ),
        (
            "subclass",
            "define laptop as a device with device.tags:'laptop'.\n\
             define work-laptop as a laptop with device.tags:'work'.\n\
             allow work-laptops to access ssh.\n",
            MV_CLIENT_SET,
        ),
        (
            "service-subclass",
            "define media-ssh as a ssh with device.tags:'media'.\n\
             allow device.tags:'phone' devices to access media-ssh.\n",
            MV_SERVER_SET,
        ),
    ];
    let temp = TempDir::new("mv-tags");

    // Pin the set forms themselves, so the comparison below cannot pass vacuously.
    let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let server_set = compile_mv_tags("server-set", MV_SERVER_SET, &temp).unwrap();
    assert_eq!(
        tag_requirements(&server_set),
        (strs(&["phone"]), strs(&["media", "server"]))
    );
    let client_set = compile_mv_tags("client-set", MV_CLIENT_SET, &temp).unwrap();
    assert_eq!(
        tag_requirements(&client_set),
        (strs(&["laptop", "work"]), strs(&["server"]))
    );

    for (name, body, set_form) in cases {
        let got = compile_mv_tags(name, &format!("{MV_SSH}{body}"), &temp)
            .unwrap_or_else(|e| panic!("case {name} must compile: {e}"));
        let want = compile_mv_tags(&format!("{name}-set"), set_form, &temp)
            .unwrap_or_else(|e| panic!("set form for {name} must compile: {e}"));
        assert_eq!(
            tag_requirements(&got),
            tag_requirements(&want),
            "case {name} must require the same tags as its set form"
        );
    }
}

#[test]
fn test_single_valued_requirements_still_conflict() {
    // zipline#185: `device.color` is single-valued, so two different required
    // values are a real contradiction and must stay a compile error.
    let cases = [
        (
            "sv-on-attr",
            "define ssh as a service with device.color:'red'.\n\
             allow device.tags:'phone' devices to access ssh on device.color:'blue' devices.\n",
        ),
        (
            "sv-class-attr",
            "define ssh as a service with device.tags:'server'.\n\
             define red as a device with device.color:'red'.\n\
             allow device.color:'blue' reds to access ssh.\n",
        ),
    ];
    let temp = TempDir::new("sv-conflict");
    for (name, zpl) in cases {
        let err = compile_mv_tags(name, zpl, &temp)
            .err()
            .unwrap_or_else(|| panic!("case {name} must fail to compile"));
        assert!(
            err.contains("conflicting values for attribute device.color"),
            "case {name}: unexpected error: {err}"
        );
    }
}

// ---- zl-zipline#226: links to nodes without a substrate address ----

/// Decode the topology of a compiled policy into
/// `(link_id, node_a substrate as "host:port" or None, node_b substrate likewise)`.
fn topology_substrates(pbytes: &[u8]) -> Vec<(String, Option<String>, Option<String>)> {
    let rdr = capnp::serialize::read_message(
        &mut Cursor::new(pbytes),
        capnp::message::ReaderOptions::new(),
    )
    .expect("decode policy");
    let policy = rdr
        .get_root::<policy_capnp::policy::Reader>()
        .expect("policy root");
    let fmt = |a: Option<zpr::policy_types::NetAddr>| a.map(|a| format!("{}:{}", a.host, a.port));
    let mut out: Vec<(String, Option<String>, Option<String>)> = policy
        .get_topology()
        .unwrap()
        .iter()
        .map(|p| {
            let peering = zpr::policy_types::Peering::try_from(p).expect("decode peering");
            (
                peering.link_id,
                fmt(peering.substrate_a),
                fmt(peering.substrate_b),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
/// A link end whose node has no substrate_addrs is written unset (never an empty host or
/// port 0), and the configured end keeps its address. Both ends may be unset.
fn test_topology_with_reported_substrate() {
    let temp = TempDir::new("topo-reported");
    let pbytes = compile_policy_bytes("test-topo-reported", &temp);
    assert_eq!(
        topology_substrates(&pbytes),
        vec![
            ("n0n1".to_string(), Some("10.0.0.1:5000".to_string()), None),
            ("n1n2".to_string(), None, None),
        ]
    );
}

#[test]
/// Naming an interface on a node that has no substrate_addrs is a configuration error.
fn test_link_interface_on_node_without_substrate_is_rejected() {
    let temp = TempDir::new("bad-link-iface-no-substrate");
    let msg = compile_expect_err("bad-link-interface-no-substrate", &temp);
    assert!(
        msg.contains("n1") && msg.contains("i0"),
        "unexpected error: {msg}"
    );
}
