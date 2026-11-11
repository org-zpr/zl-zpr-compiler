//! weaver.rs - Poetically named module that can "weave" a "fabric" from a ZPL policy and configuration.

use base64::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use zpr::policy_types::{
    AttrDomain, AttrMapping, AttrQueryConfig, Attribute, OidcConfig, ServiceType,
};

use crate::compilation::Compilation;
use crate::config_api::{ConfigApi, ConfigItem};
use crate::context::CompilationCtx;
use crate::crypto::{digest_as_hex, sha256_of_bytes};
use crate::errors::CompilationError;
use crate::fabric::{
    Fabric, FabricLink, FabricNode, NodeLinkAddr, PLine, SubstrateAddr, TrustedServiceSpec,
};
use crate::fabric_util::{squash_attributes, vec_to_attributes, vec_to_attributes_in_domain};
use crate::protocols::{PortSpec, Protocol};
use crate::ptypes::{AllowClause, Class, ClassFlavor, FPos, Policy};
use crate::zpl;

pub struct Weaver {
    fabric: Fabric,
    wctx: WeavingContext,
}

#[derive(Default)]
pub struct WeavingContext {
    // Map the allow clause ID to the fabric service ID.
    allowid_to_fab_svc: HashMap<usize, String>,

    // Track the IDs of the in-use trusted services.
    used_trusted_services: HashSet<String>,
}

/// Weave produces the fabric from the ZPL and Configuration data structures.
/// Note that the all the smarts for building the "fabric" intermediate representation
/// are here in the weaver.
///
/// Access to the configuration is via the [ConfigApi].
pub fn weave(
    comp: &Compilation,
    config: &ConfigApi,
    policy: &Policy,
    ctx: &CompilationCtx,
) -> Result<Fabric, CompilationError> {
    let mut weaver = Weaver::new(WeavingContext::default());

    let pdig = policy.digest.ok_or(CompilationError::BuildError(
        "missing policy digest".to_string(),
    ))?;

    // Use config verison as its digest. Version is hex encoded hash.
    let cdig = match config.must_get("zpr/version") {
        ConfigItem::StrVal(ver) => {
            let mut d = [0u8; 32];
            hex::decode_to_slice(ver, &mut d).map_err(|_e| {
                CompilationError::BuildError("version must be a 32 byte hex string".to_string())
            })?;
            d
        }
        _ => {
            return Err(CompilationError::ConfigError(
                "no version in configuration".to_string(),
            ));
        }
    };

    weaver.compute_revision(pdig.as_ref(), &cdig)?;

    // Create a class index which maps class name -> class struct.
    let defaults = Class::defaults();
    let mut class_idx = HashMap::new();
    // Add default classes:
    for defclass in &defaults {
        class_idx.insert(defclass.name.clone(), defclass);
    }
    for cl in &policy.defines {
        class_idx.insert(cl.name.clone(), cl);
    }

    weaver.init_services(&class_idx, policy, config)?;
    weaver.init_nodes(config, ctx)?;
    weaver.add_topology(config, ctx)?;
    // Admin policies can carry OVER clauses, whose satisfiability check needs the
    // links added by add_topology -- hence this runs here, not in init_services.
    weaver.add_visa_admin_policies(comp, &class_idx, policy, config, ctx)?;
    weaver.add_client_deny_policies(comp, &class_idx, policy, config, ctx)?;
    weaver.add_client_allow_policies(comp, &class_idx, policy, config, ctx)?;
    // By the time we get here, we have resolved all attributes and so know which trusted
    // services are in play.
    weaver.add_trusted_services(config, ctx)?;
    weaver.add_default_auth(config, ctx)?;
    weaver.add_bootstrap_records(config, ctx)?;

    Ok(weaver.fabric)
}

impl WeavingContext {
    /// Map the allow clause ID to the fabric service ID.
    fn map_allow_id_to_fabric_id<S: Into<String>>(&mut self, allow_id: usize, fab_svc_id: S) {
        self.allowid_to_fab_svc.insert(allow_id, fab_svc_id.into());
    }

    /// Get the fabric service ID for a given allow clause ID.
    fn fabric_id_for_allow_id(&self, allow_id: &usize) -> Option<&String> {
        self.allowid_to_fab_svc.get(allow_id)
    }

    fn add_used_trusted_service<S: Into<String>>(&mut self, ts_id: S) {
        self.used_trusted_services.insert(ts_id.into());
    }
}

impl Weaver {
    fn new(wctx: WeavingContext) -> Self {
        Self {
            fabric: Fabric::default(),
            wctx,
        }
    }

    fn compute_revision(
        &mut self,
        policy_digest: &[u8],
        config_digest: &[u8],
    ) -> Result<(), CompilationError> {
        let mut revhash = Vec::new();
        revhash.extend_from_slice(policy_digest);
        revhash.extend_from_slice(config_digest);
        let policy_revision_dig = sha256_of_bytes(&revhash);
        self.fabric
            .set_revision(&digest_as_hex(&policy_revision_dig));
        Ok(())
    }

    /// Figure out the set of services in the fabric.  There may be a bunch of services in
    /// the configuration but we only want the ones that are refefenced in the ZPL.
    fn init_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        self.defines_to_services(class_idx, policy, config)?;
        self.allow_clauses_to_services(class_idx, policy, config)?;
        self.visa_services_to_services()?;

        Ok(())
    }

    /// Set up the visa service(s) in the fabric.
    /// Most visa service related functionality is built in. However user can set
    /// the attributes of the administrator who is able to access the visa service
    /// admin HTTPS API.
    fn visa_services_to_services(&mut self) -> Result<(), CompilationError> {
        let vs_protocol = Protocol::tcp("zpr-vs")
            .add_port(PortSpec::Single(zpl::VISA_SERVICE_PORT))
            .build()?;

        // The provider of the visa service is a hardcoded CN value.
        let vs_cn_attr = Attribute::tuple(zpl::KATTR_CN)
            .single()
            .value(zpl::VISA_SERVICE_CN)
            .build()?;
        let vs_attrs = vec![vs_cn_attr];
        let fab_svc_id = self.fabric.add_service(
            zpl::VS_SERVICE_NAME,
            &vs_protocol,
            &vs_attrs,
            ServiceType::Visa,
        )?;

        // Visa service has policy that allows nodes to access it.  We use a node role attribute so
        // we don't care about individual node names.
        let pline = PLine::new_builtin("allow node access to visa service");
        let vs_access_attrs = vec![Attribute::try_zpr_internal_attr(zpl::KATTR_ROLE, "node")?];
        self.fabric.add_condition_to_service(
            false,
            &fab_svc_id,
            &vs_access_attrs,
            &[],
            &[], // no link constraints on the built-in visa service policy
            true,
            None,
            &pline,
        )?;

        // Now add a service for the admin HTTPS API.
        let admin_api_protocol = Protocol::tcp("zpr-vsadmin")
            .add_port(PortSpec::Single(zpl::VISA_SERVICE_ADMIN_PORT))
            .build()
            .unwrap();

        // This AMIN service is provided by the visa service too.
        self.fabric.add_builtin_service(
            &format!("{}/admin", zpl::VS_SERVICE_NAME),
            &admin_api_protocol,
            &vs_attrs,
        )?;

        // The admin access conditions themselves come from ZPL allow statements
        // and are added later, by `add_visa_admin_policies`: they may carry OVER
        // clauses, which cannot be checked against the topology until
        // `add_topology` has populated the fabric links.

        // TODO: When we get around to trusted services, we need to add builtin rules
        //       that grant VS access to the trusted services.
        //       And adapters also have rules (to access the OAuth endpoints).
        Ok(())
    }

    /// Add the admin API access conditions from ZPL allow statements that target
    /// the visa service. Must run after `add_topology`: an OVER clause on such a
    /// statement is checked for satisfiability against the configured links,
    /// exactly like on a regular service policy.
    fn add_visa_admin_policies(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let fab_admin_svc_id = format!("{}/admin", zpl::VS_SERVICE_NAME);

        // The admin permissions come from ZPL allow statements, not from configuration.
        let mut condition_count = 0;
        for (plcy_idx, ac) in policy.allows.iter().enumerate() {
            // Seeking a RHS service class that is the visa service.

            let vs_rhs_count = ac
                .server
                .iter()
                .filter(|c| {
                    c.flavor == ClassFlavor::Service && c.class == zpl::DEF_CLASS_VISA_SERVICE_NAME
                })
                .count();
            if vs_rhs_count < 1 {
                continue;
            }

            // TODO: User may be able to shoot themselves in the foot here if they add
            // too many attributes to VisaService. May want to consider disallowing
            // any attributes on the service (but allow on user and device).

            // The admin access attributes are all the attributes declared on the client side of
            // the clause.
            //
            // TODO: Where do we add the service side attributes for visa service?
            let mut admin_access_attrs = Vec::new();

            for lhs_clause in &ac.client {
                // Add the attributes from this clause
                admin_access_attrs.extend_from_slice(&lhs_clause.with);

                // And add the attributes defined at class level
                admin_access_attrs
                    .extend_from_slice(&attrs_for_class(class_idx, &lhs_clause.class)?);
            }

            let fp = FPos::from(&ac.server[0].class_tok);
            let resolved_attrs = self.resolve_and_squash(&admin_access_attrs, &fp, config)?;

            // Link constraints from the statement's OVER clause. Without this, a
            // policy like "allow admins to access VisaService over secure links"
            // would grant admin access over ANY link -- the constraint must flow
            // through the same squashing and satisfiability flow as for regular
            // services.
            let link_required_attrs = self.link_conditions_for_clause(ac, &fp, ctx)?;

            let pline = PLine::new(ac.span.0.line, &comp.zpl_for_allow_statement(plcy_idx));
            if !resolved_attrs.is_empty() {
                self.fabric.add_condition_to_service(
                    false,
                    &fab_admin_svc_id,
                    &resolved_attrs,
                    &[], // TODO: Should we consider RHS attributes?
                    &link_required_attrs,
                    false,
                    None,
                    &pline,
                )?;
                condition_count += 1;
            }
        }
        if condition_count == 0 {
            // TODO: is this an error?
            ctx.warn("no policy granting admin access to VisaService")?;
        }
        Ok(())
    }

    /// Make sure that any service defines are reflected in policy so that proper service
    /// attributes get set up at connect time.
    fn defines_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        for define in &policy.defines {
            if define.flavor != ClassFlavor::Service {
                continue;
            }
            // An actor can connect and offer the service if it is able to satisfy the
            // set of attributes attached to it through the define or configuration.
            //
            // TODO: If there are no allow rules that permit access to the service then
            // maybe we don't even allow it to connect?
            let mut attrs = Vec::new();
            let svc_class_attrs = attrs_for_class(class_idx, &define.name)?;
            attrs.extend_from_slice(&svc_class_attrs);
            self.add_service(class_idx, define, &attrs, define.class_id, config)?;
        }
        Ok(())
    }

    fn add_service(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        sclass: &Class,
        initial_attrs: &[Attribute],
        svc_id: usize,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        let service_name = &sclass.name;
        let mut attrs = Vec::new();
        attrs.extend_from_slice(initial_attrs);

        // Service class either match an ID in the configuration or must have a
        // parent that does.  We take the first parent that matches a configuration as
        // the service configuration to use.
        //

        let matched_service_name = find_defined_service(service_name, config, class_idx);
        if matched_service_name.is_none() {
            return Err(CompilationError::ConfigError(format!(
                "no service for {} found in configuration",
                service_name
            )));
        }
        let matched_service_name = matched_service_name.unwrap();

        // The service may have provider attributes that we need.
        match config.get(&format!("/services/{}/provider", matched_service_name)) {
            Some(citem) => match citem {
                ConfigItem::AttrList(alist) => {
                    attrs.extend_from_slice(&vec_to_attributes(&alist)?);
                }
                _ => {
                    return Err(CompilationError::BuildError(format!(
                        "provider not an attribute list: {matched_service_name}"
                    )));
                }
            },
            None => {
                // no provider attributes
            }
        };

        // service must have a protocol
        let prot = match config.get(&format!("/services/{}/protocol", matched_service_name)) {
            Some(citem) => match &citem {
                ConfigItem::Protocol(_, _, _) => citem.try_into_protocol()?,
                _ => {
                    return Err(CompilationError::BuildError(format!(
                        "protocol not a protocol enum: {matched_service_name}"
                    )));
                }
            },
            None => {
                return Err(CompilationError::ConfigError(format!(
                    "protocol for {} not found in configuration",
                    matched_service_name,
                )));
            }
        };

        let resolved_attrs = self.resolve_and_squash(&attrs, &sclass.pos, config)?;

        if resolved_attrs.is_empty() {
            return Err(CompilationError::ConfigError(format!(
                "service with no attributes: '{}'",
                matched_service_name
            )));
        }

        let fabric_svc_id = self.fabric.add_service(
            &matched_service_name,
            &prot,
            &resolved_attrs,
            ServiceType::Regular,
        )?;
        self.wctx.map_allow_id_to_fabric_id(svc_id, fabric_svc_id);
        Ok(())
    }

    /// This requires that `add_services` has already been run.
    ///
    /// Errors out if:
    /// * `name` is not in the `class_idx`
    /// * the class ID for `name` is not in the fabric services map.
    fn service_clause_name_to_fabric_id(
        &self,
        class_idx: &HashMap<String, &Class>,
        name: &str,
    ) -> Result<String, CompilationError> {
        let svc_id = match class_idx.get(name) {
            Some(cls) => cls.class_id,
            None => {
                return Err(CompilationError::BuildError(format!(
                    "service class {name} not found in class index"
                )));
            }
        };
        let fab_svc_id = match self.wctx.fabric_id_for_allow_id(&svc_id) {
            Some(s) => s,
            None => {
                // programming error
                return Err(CompilationError::BuildError(format!(
                    "service {name} with id {svc_id} not found in fabric map"
                )));
            }
        };
        Ok(fab_svc_id.clone())
    }

    fn allow_clauses_to_services(
        &mut self,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
    ) -> Result<(), CompilationError> {
        for ac in &policy.allows {
            // Parser ensures that the allow clause has a server.service clause.
            let server_service = ac.get_server_service_clause().unwrap();
            if server_service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // ZPL that applies to ALL services does not generate additional
                // connect rules.  But it will create access rules.
                continue;
            }
            if server_service.class == zpl::DEF_CLASS_VISA_SERVICE_NAME {
                // Handled elswhere.
                continue;
            }

            let svc_id = match class_idx.get(&server_service.class) {
                Some(cls) => cls.class_id,
                None => {
                    return Err(CompilationError::BuildError(format!(
                        "service class {} not found in class index",
                        server_service.class
                    )));
                }
            };

            // start with parent class attributes
            let mut attrs = attrs_for_class(class_idx, &server_service.class)?;

            // And include any additional server side attributes from the RHS clause.
            // The authority presence markers are excluded: they assert a live
            // runtime authentication checked per-connection (svc_condition),
            // not a configured provider attribute -- folding one in here would
            // fork a service variant whose provider set can never match a
            // configured provider, and add_condition_to_service would then
            // drop the marker from the service conditions as "already a
            // provider attribute" (issue #144).
            for rhs_clause in &ac.server {
                attrs.extend(
                    rhs_clause
                        .with
                        .iter()
                        .filter(|a| !zpl::is_authority_marker_key(&a.zpl_key()))
                        .cloned(),
                );
            }
            let svc_class =
                class_idx
                    .get(&server_service.class)
                    .ok_or(CompilationError::BuildError(format!(
                        "service class {} not found in class index",
                        server_service.class
                    )))?;
            self.add_service(class_idx, svc_class, &attrs, svc_id, config)?;
        }
        Ok(())
    }

    // Every attribute needs to come from a trusted service.
    //
    // As a side effect, this updates our local set of in-use trusted services.
    //
    /// Resolve `attrs` against the trusted services, then squash duplicates.
    ///
    /// The order matters: resolution is what marks an attribute multi-valued (from
    /// the service's `name{}` mapping), and [squash_attributes] combines two values
    /// of a multi-valued attribute but rejects them on a single-valued one
    /// (zipline#185). `fp` is the position reported for a conflict.
    fn resolve_and_squash(
        &mut self,
        attrs: &[Attribute],
        fp: &FPos,
        config: &ConfigApi,
    ) -> Result<Vec<Attribute>, CompilationError> {
        let resolved = self.resolve_attributes(attrs, config)?;
        Ok(squash_attributes(&resolved, fp)?.into_values().collect())
    }

    fn resolve_attributes(
        &mut self,
        attrs: &[Attribute],
        config: &ConfigApi,
    ) -> Result<Vec<Attribute>, CompilationError> {
        let trusted_service_names = config.must_get_keys("/trusted_services");

        let mut resolved_attrs = Vec::new();
        for zpl_attr in attrs {
            let attr_name = zpl_attr.zpl_key();
            if zpl_attr.is_tag() && zpl_attr.zplc_key() == format!("#{}", zpl::KATTR_CN) {
                return Err(CompilationError::ConfigError(format!(
                    "{} attribute used as a tag, but is a tuple attribute",
                    zpl_attr.to_instance_string(),
                )));
            }

            match attr_name.as_str() {
                zpl::KATTR_CN => {
                    resolved_attrs.push(zpl_attr.clone());
                    self.wctx
                        .add_used_trusted_service(zpl::DEFAULT_TRUSTED_SERVICE_ID);
                }
                zpl::DEFAULT_ATTR => {
                    resolved_attrs.push(zpl_attr.clone_with_new_name(zpl::KATTR_CN)?);
                    self.wctx
                        .add_used_trusted_service(zpl::DEFAULT_TRUSTED_SERVICE_ID);
                }
                zpl::KATTR_SERVICES => {
                    resolved_attrs.push(zpl_attr.clone());
                    self.wctx
                        .add_used_trusted_service(zpl::DEFAULT_TRUSTED_SERVICE_ID);
                }
                // Note there is deliberately no arm for zpl::KATTR_ADDR here
                // (zipline#109): an authored `zpr.addr` provider pin is rejected
                // in vec_to_attributes before resolution, and the node emitter
                // (init_nodes) constructs the node's `zpr.addr` attribute AFTER
                // its provider attributes are resolved, so the key never reaches
                // this function. An unexpected occurrence falls through to the
                // "not found in any trusted service" rejection below.
                // The authority presence markers are installed by the visa
                // service when a live authentication exists for that namespace
                // (issue #144) -- they are not attributes an external trusted
                // service reports. They live in the ZPR-owned `zpr.` sub-
                // namespace, which declared trusted services cannot claim
                // (rejected in config::trusted_service::parse_return_mappings),
                // so resolving them to the default trusted service here is
                // sound. The match is on the key, so an authored constraint
                // such as `user.zpr.authority:google` resolves through this
                // same arm.
                zpl::KATTR_USER_AUTHORITY | zpl::KATTR_DEVICE_AUTHORITY => {
                    resolved_attrs.push(zpl_attr.clone());
                    self.wctx
                        .add_used_trusted_service(zpl::DEFAULT_TRUSTED_SERVICE_ID);
                }
                _ => {
                    // TODO: This should be cached
                    // TODO: Not sure we are handling the case where ZPL is using prefixes correctly here.
                    let mut matched = false;
                    for ts_name in &trusted_service_names {
                        let ts_attrs = config.must_get_attr_mappings(&format!(
                            "/trusted_services/{}/attributes",
                            ts_name
                        ));

                        // "a" is the attribute referenced in the ZPL, so it appears on the RHS
                        // (the decoded `mapping.attr`) of a return mapping. The LHS
                        // (`service_attr_key`) is the raw name the service reports.

                        // As we search we need to consider that a tuple type attribute could match
                        // either the service plain key eg, "user.role" or the service multi-value key, eg, "user.role{}".
                        let search_str = zpl_attr.zplc_key();
                        let alt_search_str = if !zpl_attr.is_tag() && !zpl_attr.is_multi_valued() {
                            Some(format!("{}{{}}", search_str))
                        } else {
                            None
                        };

                        let found = ts_attrs.iter().find(|m| {
                            m.attr.zplc_key() == search_str
                                || alt_search_str.is_some()
                                    && &m.attr.zplc_key() == alt_search_str.as_ref().unwrap()
                        });

                        if let Some(mapping) = found {
                            if matched {
                                return Err(CompilationError::ConfigError(format!(
                                    "attribute {} found in multiple trusted services",
                                    zpl_attr.to_instance_string()
                                )));
                            }
                            let mut new_attr = zpl_attr.clone();
                            // If the service indicates that this attribute is multi-valued then we keep that info.
                            if mapping.attr.is_multi_valued() {
                                new_attr.set_multi_valued()?;
                            }
                            resolved_attrs.push(new_attr);
                            self.wctx.add_used_trusted_service(ts_name.clone());
                            matched = true;
                        }
                    }
                    if !matched {
                        return Err(CompilationError::ConfigError(format!(
                            "attribute {} not found in any trusted service",
                            zpl_attr.to_instance_string()
                        )));
                    }
                }
            }
        }
        Ok(resolved_attrs)
    }

    /// Must init_services before init_nodes.
    fn init_nodes(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let node_keys = match config.get("zpr/nodes") {
            Some(ConfigItem::KeySet(node_ids)) => node_ids,
            _ => {
                return Err(CompilationError::ConfigError(
                    "no nodes defined in configuration".to_string(),
                ));
            }
        };

        match config.get("zpr/visa_services/default/dock_node_id") {
            Some(ConfigItem::StrVal(_node_id)) => {
                ctx.warn("visa service has docking node set but is not enforced")?;
            }
            _ => (),
        };

        for node_key in &node_keys {
            let raw_node_attrs = match config.get(&format!("zpr/nodes/{node_key}/provider")) {
                Some(ConfigItem::AttrList(attrs)) => vec_to_attributes(&attrs)?,
                _ => {
                    return Err(CompilationError::ConfigError(format!(
                        "node {node_key} missing provider attributes",
                    )));
                }
            };
            let mut resolved_node_attrs = self.resolve_attributes(&raw_node_attrs, config)?;

            let zpr_addr = match config.get(&format!("zpr/nodes/{node_key}/zpr_addr")) {
                Some(ConfigItem::StrVal(s)) => s,
                _ => {
                    return Err(CompilationError::ConfigError(format!(
                        "missing zpr address for node {}",
                        node_key
                    )));
                }
            };

            // The address returned from config-api has already gone though the resolver.
            // We require an IPv6 address.
            let naddr: Ipv6Addr = match zpr_addr.parse() {
                // TODO: Should be parsed to an IpAddr in config.rs
                Ok(a) => a,
                Err(e) => {
                    return Err(CompilationError::ConfigError(format!(
                        "invalid zpr IPv6 address for node: {}: {}",
                        zpr_addr, e
                    )));
                }
            };

            resolved_node_attrs.push(Attribute::try_zpr_internal_attr(
                zpl::KATTR_ADDR,
                &naddr.to_string(),
            )?);

            // Note that we do not have line/col info from the config file.
            let attr_map = squash_attributes(&resolved_node_attrs, &FPos::default())?;
            let provider_attrs = attr_map.into_values().collect::<Vec<Attribute>>();

            // Gather the nodes named substrate addrs if any.
            let substrates = match config.get(&format!("zpr/nodes/{node_key}/interfaces")) {
                Some(ConfigItem::KeySet(if_ids)) => {
                    let mut interfaces = HashMap::new();
                    for if_id in &if_ids {
                        match config.get(&format!("zpr/nodes/{node_key}/interfaces/{if_id}")) {
                            Some(ConfigItem::NetAddr(host, port)) => {
                                let if_addr = SubstrateAddr {
                                    host: host.clone(),
                                    port: port,
                                };
                                interfaces.insert(if_id.to_string(), if_addr);
                            }
                            _ => {
                                return Err(CompilationError::ConfigError(format!(
                                    "interface {if_id} for node {node_key} must be a network address",
                                )));
                            }
                        }
                    }
                    Some(interfaces)
                }
                _ => None,
            };

            let fabn = FabricNode {
                node_id: node_key.to_string(),
                zpr_addr: naddr.into(),
                provider_attrs: provider_attrs.clone(),
                substrate_addrs: substrates,
            };

            self.fabric.push_node(fabn);

            // Now create the visa support service for this node and an access rule.
            let vs = self
                .fabric
                .get_visa_service()
                .ok_or(CompilationError::BuildError(
                    "visa service must be added before add_node is called".to_string(),
                ))?;
            let vs_provider_attrs = vs.provider_attrs.clone();
            let svc_name = format!("zpr/{}/vss", node_key);

            // There cannot be a service with this id already.
            if self.fabric.has_service(&svc_name) {
                return Err(CompilationError::ConfigError(format!(
                    "unabled to configure node VSS because service {} already exists in fabric",
                    &svc_name
                )));
            }

            let vss_prot = Protocol::tcp("zpr-vss")
                .add_port(PortSpec::Single(zpl::VISA_SUPPORT_SEVICE_PORT))
                .build()
                .unwrap();
            let vss_id = self
                .fabric
                .add_builtin_service(&svc_name, &vss_prot, &provider_attrs)?;
            let pline = PLine::new_builtin("allow visa service to access node visa support");
            self.fabric.add_condition_to_service(
                false,
                &vss_id,
                &vs_provider_attrs,
                &[],
                &[], // no link constraints on the visa support service policy
                false,
                None,
                &pline,
            )?;
        }
        Ok(())
    }

    /// Look up one end of a link: the node's ZPR address and the substrate address of
    /// interface `if_id`. An empty `if_id` means the node has no substrate address in the
    /// configuration (it reports its own at run time), so the substrate is `None`
    /// (zl-zipline#226).
    fn get_node_link_addr(
        &self,
        node_key: &str,
        if_id: &str,
    ) -> Result<NodeLinkAddr, CompilationError> {
        let node = self
            .fabric
            .get_node(node_key)
            .ok_or(CompilationError::BuildError(format!(
                "linked node {node_key} not found in fabric",
            )))?;
        let substrate = if if_id.is_empty() {
            None
        } else {
            let if_addr = node
                .substrate_addrs
                .as_ref()
                .ok_or(CompilationError::ConfigError(format!(
                    "node {node_key} is part of a link but has no substrate interfaces defined",
                )))?
                .get(if_id)
                .ok_or(CompilationError::ConfigError(format!(
                    "interface {if_id} not found for linked node {node_key}",
                )))?;
            Some(if_addr.clone())
        };

        Ok(NodeLinkAddr {
            zpr_addr: node.zpr_addr.clone(),
            substrate,
        })
    }

    /// Uses the Fabric nodes, so must be called after setting up the nodes in the fabric.
    fn add_topology(
        &mut self,
        config: &ConfigApi,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let link_ids = match config.get("zpr/links") {
            Some(ConfigItem::KeySet(link_ids)) => link_ids,
            _ => return Ok(()),
        };
        for link_id in &link_ids {
            let link_tuple = match config.get(&format!("zpr/links/{link_id}")) {
                Some(ConfigItem::KeySet(tup)) => tup,
                _ => {
                    return Err(CompilationError::ConfigError(format!(
                        "missing or invalid link: {link_id}",
                    )));
                }
            };
            // Expect: (node1, ifname1, node2, ifname2)
            if link_tuple.len() != 4 {
                return Err(CompilationError::BuildError(format!(
                    "link {link_id} must be a tuple of (node1, ifname1, node2, ifname2)",
                )));
            }

            let link_attrs = match config.get(&format!("zpr/links/{link_id}/attributes")) {
                Some(ConfigItem::AttrList(attrs)) => {
                    vec_to_attributes_in_domain(&attrs, AttrDomain::Link)?
                }
                _ => vec![],
            };

            let flink = FabricLink {
                link_id: link_id.to_string(),
                node_a: self.get_node_link_addr(&link_tuple[0], &link_tuple[1])?,
                node_b: self.get_node_link_addr(&link_tuple[2], &link_tuple[3])?,
                link_attrs: link_attrs,
            };

            self.fabric.push_link(flink);
        }

        Ok(())
    }

    /// Extract, squash and satisfiability-check the link conditions from a
    /// statement's OVER clause. Returns an empty vec when the statement has no
    /// OVER clause. Used by both the regular service policy path and the
    /// VisaService admin policy path so the two cannot diverge.
    ///
    /// Note the conditions are deliberately NOT passed through
    /// `resolve_attributes`: link attributes are not vouched for by a trusted
    /// service, they come from the topology in the configuration description
    /// (see `init_links`, which reads `zpr/links/<id>/attributes`). Resolving
    /// them would fail with "attribute not found in any trusted service".
    fn link_conditions_for_clause(
        &self,
        ac: &AllowClause,
        fp: &FPos,
        ctx: &CompilationCtx,
    ) -> Result<Vec<Attribute>, CompilationError> {
        match &ac.link {
            Some(link_clause) => {
                let link_attrs: Vec<Attribute> = link_clause
                    .with
                    .iter()
                    .filter(|a| !a.optional)
                    .cloned()
                    .collect();
                let attr_map = squash_attributes(&link_attrs, fp)?;
                let conds = attr_map.into_values().collect::<Vec<Attribute>>();
                self.check_link_conditions_satisfiable(&conds, &ac.span.0, ctx)?;
                Ok(conds)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Check an `over` clause against the configured topology.
    ///
    /// ZPLC (the topology) and ZPL are always compiled together, so at this point we know
    /// every link in the fabric and the attributes it carries. Two distinct mistakes are
    /// possible, and they are treated differently:
    ///
    /// - **Unknown attribute (error).** No configured link carries an attribute with this
    ///   `zpl_key()`. The statement is dead — it can never grant, and for a `never allow`
    ///   can never deny, anything. That is a policy authoring mistake, so the compile fails
    ///   rather than silently emitting an unsatisfiable rule.
    /// - **Unknown value (warning).** The attribute exists on some link, but no link
    ///   currently carries the value the clause names. This is usually a typo
    ///   (`location:use` for `location:usa`), which is why it is reported, but it is not
    ///   fatal: link values are topology data that a later configuration edit may
    ///   legitimately introduce, and RFC 15 leaves value matching to the visa service at
    ///   enforcement time. `--werror` promotes it to an error for callers who want that.
    ///
    /// Tags have no values, so only the key check applies to them.
    fn check_link_conditions_satisfiable(
        &self,
        conds: &[Attribute],
        pos: &FPos,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for cond in conds {
            let key = cond.zpl_key();
            let matching_attrs = self
                .fabric
                .links
                .iter()
                .flat_map(|link| link.link_attrs.iter())
                .filter(|la| la.zpl_key() == key)
                .collect::<Vec<&Attribute>>();

            if matching_attrs.is_empty() {
                return Err(CompilationError::ZPLError(
                    format!(
                        "link attribute '{}' in OVER clause is not present on any configured link, \
                         so this statement can never match",
                        cond.to_instance_string(),
                    ),
                    pos.line,
                    pos.col,
                ));
            }

            // The key exists; check the values the clause asks for. A value no link
            // carries today is a likely typo but not fatal -- warn only.
            for value in cond.zpl_values() {
                let value_present = matching_attrs
                    .iter()
                    .any(|la| la.zpl_values().iter().any(|v| *v == value));
                if !value_present {
                    let configured = {
                        let mut vals = matching_attrs
                            .iter()
                            .flat_map(|la| la.zpl_values())
                            .collect::<Vec<String>>();
                        vals.sort();
                        vals.dedup();
                        vals
                    };
                    ctx.warn(&format!(
                        "line {}: link attribute '{}' in OVER clause has value '{}', \
                         which is not present on any configured link (configured values: {})",
                        pos.line,
                        key,
                        value,
                        if configured.is_empty() {
                            "none".to_string()
                        } else {
                            configured.join(", ")
                        },
                    ))?;
                }
            }
        }
        Ok(())
    }

    /// Process the ZPL policy into conditions for accessing fabric services.
    /// Must be done after initializing the services.
    fn add_client_allow_policies(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and device clauses.
        self.add_client_policies_allow_or_deny(comp, &policy.allows, false, class_idx, config, ctx)
    }

    fn add_client_deny_policies(
        &mut self,
        comp: &Compilation,
        class_idx: &HashMap<String, &Class>,
        policy: &Policy,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        // Every allow is an access condition (aka rule, aka policy).
        // We need the attributes from the user and device clauses.
        self.add_client_policies_allow_or_deny(comp, &policy.nevers, true, class_idx, config, ctx)
    }

    fn add_client_policies_allow_or_deny(
        &mut self,
        comp: &Compilation,
        allow_clause: &[AllowClause],
        never_allow: bool,
        class_idx: &HashMap<String, &Class>,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        for (i, ac) in allow_clause.iter().enumerate() {
            let server_service = ac.get_server_service_clause().unwrap();
            if server_service.class == zpl::DEF_CLASS_VISA_SERVICE_NAME {
                // Visa service is handled separately.
                continue;
            }

            // Here we collect all attributes -- some will have no values.
            let mut attrs = Vec::new();

            // Grab the LHS device, service and user attributes.
            for lhs_class in &ac.client {
                if lhs_class.flavor == ClassFlavor::Device
                    || lhs_class.flavor == ClassFlavor::User
                    || lhs_class.flavor == ClassFlavor::Service
                {
                    // Add attributes from parent
                    attrs.extend_from_slice(&attrs_for_class(class_idx, &lhs_class.class)?);

                    // Add non-optional instance attributes
                    attrs.extend(lhs_class.with.iter().filter(|a| !a.optional).cloned());

                    // If there is a service clause on the LHS then we assert that the
                    // connecting client is a provider of that service. Note, there may not
                    // be a concrete service specified, in that case we just say client must be
                    // a provider of ANY service.
                    if lhs_class.flavor == ClassFlavor::Service {
                        let svc_attr = if lhs_class.class == zpl::DEF_CLASS_SERVICE_NAME {
                            Attribute::try_zpr_internal_attr_mv(zpl::KATTR_SERVICES, "")?
                        } else {
                            let fab_svc_name =
                                self.service_clause_name_to_fabric_id(class_idx, &lhs_class.class)?;
                            Attribute::try_zpr_internal_attr_mv(zpl::KATTR_SERVICES, &fab_svc_name)?
                        };
                        attrs.push(svc_attr);
                    }
                }
            }

            // Now we consolidate the attributes into a map, preferring attributes that have a value.
            let fp = FPos::from(server_service.class_tok);
            let required_attrs = self.resolve_and_squash(&attrs, &fp, config)?;

            // Now grab the RHS attributes (attributes for the server)
            let svc_required_attrs = {
                let mut service_class_attrs = Vec::new();
                for rhs_class in &ac.server {
                    service_class_attrs
                        .extend(rhs_class.with.iter().filter(|a| !a.optional).cloned());
                }
                self.resolve_and_squash(&service_class_attrs, &fp, config)?
            };

            // And the link constraints from the OVER clause, if the statement had one.
            // These are recorded in the policy for the visa service to enforce; the
            // compiler does not itself check that a satisfying path exists.
            let link_required_attrs = self.link_conditions_for_clause(ac, &fp, ctx)?;

            // Now figure out what service we are talking about.
            // The service may be:
            // a) a service that is defined in configuration, eg "SomeDatabase"
            // b) a service that is defined in ZPL as a child of a service defined in configuration.
            // c) the base service, eg, "service" - "allow red users to access services" -- in which case this condition applied to
            //    all services.

            let pline = PLine {
                lineno: ac.span.0.line,
                zpl: if never_allow {
                    comp.zpl_for_never_allow_statement(i)
                } else {
                    comp.zpl_for_allow_statement(i)
                },
            };

            if server_service.class == zpl::DEF_CLASS_SERVICE_NAME {
                // Add to all services (not nodes or trusted services or visa service)
                let regular_svc_ids = self
                    .fabric
                    .services
                    .iter()
                    .filter(|s| s.service_type == ServiceType::Regular)
                    .map(|s| s.fabric_id.clone())
                    .collect::<Vec<String>>();
                for svc_id in &regular_svc_ids {
                    self.fabric.add_condition_to_service(
                        never_allow,
                        &svc_id,
                        &required_attrs,
                        &svc_required_attrs,
                        &link_required_attrs,
                        false, // guessing
                        ac.signal.clone(),
                        &pline,
                    )?;
                }
            } else {
                let fab_svc_id =
                    self.service_clause_name_to_fabric_id(class_idx, &server_service.class)?;
                self.fabric.add_condition_to_service(
                    never_allow,
                    &fab_svc_id,
                    &required_attrs,
                    &svc_required_attrs,
                    &link_required_attrs,
                    false,
                    ac.signal.clone(),
                    &pline,
                )?;
            }
        }
        Ok(())
    }

    /// For now we only accept the DEFAULT (builtin) trusted service.
    /// And the only thing we care about is the certificate.
    fn add_default_auth(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        if config
            .get(&format!(
                "/trusted_services/{}",
                zpl::DEFAULT_TRUSTED_SERVICE_ID
            ))
            .is_none()
        {
            return Err(CompilationError::ConfigError(
                "no trusted default service found in configuration".to_string(),
            ));
        }

        let cert_data = match config.get(&format!(
            "/trusted_services/{}/certificate",
            zpl::DEFAULT_TRUSTED_SERVICE_ID
        )) {
            Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                Ok(cert_data) => cert_data,
                Err(e) => {
                    return Err(CompilationError::ConfigError(format!(
                        "error decoding certificate data: {}",
                        e
                    )));
                }
            },
            _ => {
                // TODO: This should probably be an error, but helps for testing.
                ctx.warn("no certificate for default trusted service")?;
                vec![]
            }
        };

        self.fabric.set_default_auth_cert(cert_data);
        Ok(())
    }

    /// Resolve the provider attributes of every on-net service a used trusted service
    /// depends on (today only an `oidc` service's JWKS proxy). This may add to the list
    /// of active trusted services -- since it's possible that some trusted services are
    /// only used when defining the providers of other trusted services.
    fn resolve_trusted_service_providers(
        &mut self,
        config: &ConfigApi,
        _ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let mut checked_services = HashSet::new();
        loop {
            let active_set_count = self.wctx.used_trusted_services.len();
            let active_trusted_services = self.wctx.used_trusted_services.clone();
            for ts_name in &active_trusted_services {
                if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                    continue;
                }
                if checked_services.contains(ts_name) {
                    continue;
                }
                checked_services.insert(ts_name.clone());

                // No trusted service has provider attributes of its own: a `file` service is
                // offered by the Visa Service itself, and `oidc` and `zpr-attr/1` services are
                // off-net. The only on-net dependency is an `oidc` declaration's optional JWKS
                // proxy `service`; that service's provider attributes take part in the
                // dependency closure like any other provider attributes, otherwise a trusted
                // service used only by the proxy provider is discovered after this closure is
                // snapshotted and never woven. Existence/shape errors are deferred to
                // add_oidc_trusted_service, which reports them with context.
                let ts_api = config
                    .must_get(&format!("/trusted_services/{ts_name}/api"))
                    .to_string();
                if ts_api != zpl::TS_API_OIDC {
                    continue;
                }
                if let Some(ConfigItem::StrVal(name)) =
                    config.get(&format!("/trusted_services/{ts_name}/vs_service"))
                {
                    if let Some(ConfigItem::AttrList(alist)) =
                        config.get(&format!("/services/{name}/provider"))
                    {
                        let proxy_provider_attrs = vec_to_attributes(&alist)?;
                        // Call resolve which may add to the list of active trusted services.
                        let _ = self.resolve_attributes(&proxy_provider_attrs, config)?;
                    }
                }
            }
            if self.wctx.used_trusted_services.len() == active_set_count {
                break; // no change? We are done.
            }
        }
        Ok(())
    }

    /// Retain every trusted service that vends identity attributes, whether or not
    /// any ZPL statement references its returned attributes.
    ///
    /// A trusted service declaring a non-empty `identity_attributes` is a query key
    /// for every attribute store in the policy -- a `file` store's JSON is keyed by
    /// identity attribute and value -- so whether ZPL references *its own* returned
    /// attributes says nothing about whether the visa service needs it. Only `oidc`
    /// can reach this rule: the config parser rejects `identity_attributes` on
    /// `api = "file"`, on `api = "zpr-attr/1"` and on the default service. Identity
    /// vendors are never pruned; attribute overlays still are.
    ///
    /// The compiler cannot see a file store's JSON keys, so it cannot prove an
    /// identity vendor is unused. The `ctx.info()` line makes each such retention
    /// visible at build time (`info`, not `warn` -- for `oidc` this is the normal
    /// case and must not trip `--Werror`).
    fn retain_identity_vendors(&mut self, config: &ConfigApi, ctx: &CompilationCtx) {
        let mut ts_names = config.must_get_keys("/trusted_services");
        ts_names.sort(); // deterministic diagnostics
        for ts_name in ts_names {
            if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                continue;
            }
            let id_attrs = match config.get(&format!("/trusted_services/{ts_name}/id_attributes")) {
                Some(ConfigItem::KeySet(attrs)) => attrs,
                _ => Vec::new(),
            };
            if id_attrs.is_empty() || self.wctx.used_trusted_services.contains(&ts_name) {
                continue;
            }
            ctx.info(&format!(
                "trusted service `{ts_name}` retained: vends identity attributes"
            ));
            self.wctx.add_used_trusted_service(ts_name);
        }
    }

    /// Retain every trusted service that vends an attribute the visa service
    /// itself interprets (`zpl::KATTR_VS_INTERPRETED`: `device.zpr_addr`,
    /// `device.hostname`), whether or not any ZPL statement references its
    /// returned attributes (zipline#105).
    ///
    /// Without this rule a store vending only these attributes is pruned with
    /// no error, and the deployment silently misbehaves: the device comes up on
    /// a pool address instead of its static grant, or the DNS hosts index stays
    /// empty. Any trusted-service API qualifies (`file`, `zpr-attr/1`,
    /// `oidc`), because any declared service may grant.
    ///
    /// Known trade-off, accepted in zipline#105: an unused networked store that
    /// happens to vend one of these attributes is now woven, giving the visa
    /// service a network dependency it previously pruned -- the same price as
    /// `retain_identity_vendors`. The `ctx.info()` line makes each retention
    /// visible at build time (`info`, not `warn`, so it cannot trip `--Werror`).
    fn retain_vs_interpreted_providers(&mut self, config: &ConfigApi, ctx: &CompilationCtx) {
        let mut ts_names = config.must_get_keys("/trusted_services");
        ts_names.sort(); // deterministic diagnostics
        for ts_name in ts_names {
            if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID
                || self.wctx.used_trusted_services.contains(&ts_name)
            {
                continue;
            }
            let mappings =
                config.must_get_attr_mappings(&format!("/trusted_services/{ts_name}/attributes"));
            // Compare the decoded `Attribute` (domain + zpl_key), not the raw
            // `zpr_attr_spec`, so the `{}` multi-valued spelling and any
            // whitespace in the config do not matter.
            let vs_interpreted = mappings.iter().find(|m| {
                *m.attr.get_domain_ref() == AttrDomain::Device
                    && zpl::KATTR_VS_INTERPRETED.contains(&m.attr.zpl_key().as_str())
            });
            if let Some(mapping) = vs_interpreted {
                ctx.info(&format!(
                    "trusted service `{ts_name}` retained: vends visa-service-interpreted \
                     attribute `{}`",
                    mapping.attr.zpl_key()
                ));
                self.wctx.add_used_trusted_service(ts_name);
            }
        }
    }

    /// Add non-default trusted services to the fabric.
    fn add_trusted_services(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        // Identity vendors are retained before the provider fixpoint runs, so a
        // retained `oidc` service's JWKS proxy provider attributes still resolve
        // through it.
        self.retain_identity_vendors(config, ctx);
        // Same ordering argument for vendors of visa-service-interpreted
        // attributes (zipline#105): retain before the provider fixpoint so a
        // retained service's provider attributes still resolve.
        self.retain_vs_interpreted_providers(config, ctx);
        self.resolve_trusted_service_providers(config, ctx)?;

        // Copy the used trusted service names into a stand alone, sorted vector: it avoids
        // holding an immutable ref to self in the loop below and gives deterministic weave order.
        let mut used_trusted_service_names: Vec<String> =
            self.wctx.used_trusted_services.iter().cloned().collect();
        used_trusted_service_names.sort();

        for ts_name in used_trusted_service_names {
            if ts_name == zpl::DEFAULT_TRUSTED_SERVICE_ID {
                continue;
            }

            let ts_api = config
                .must_get(&format!("/trusted_services/{ts_name}/api"))
                .to_string();

            // Return mappings and expiration are common to every trusted-service API.
            let ts_returns_attrs =
                config.must_get_attr_mappings(&format!("/trusted_services/{ts_name}/attributes"));
            let expiration_seconds =
                config.must_get_u32(&format!("/trusted_services/{ts_name}/expiration_seconds"));

            // A `file` service has no network presence (no client/vs interface, provider, cert, or
            // protocol). It is offered by the Visa Service (vs.zpr) itself, so it lands in the VS
            // join policy via the ServiceType::Trusted path with an empty endpoint list, and gets
            // no communication policy.
            if ts_api == zpl::TS_API_FILE {
                let vs_cn_attr = Attribute::tuple(zpl::KATTR_CN)
                    .single()
                    .value(zpl::VISA_SERVICE_CN)
                    .build()?;
                self.fabric
                    .add_trusted_service(TrustedServiceSpec {
                        id: ts_name.clone(),
                        api: ts_api.clone(),
                        provider_attrs: vec![vs_cn_attr],
                        returns_attrs: ts_returns_attrs,
                        expiration_seconds,
                        ..Default::default()
                    })
                    .map_err(|e| {
                        CompilationError::ConfigError(format!(
                            "error adding trusted service: {}",
                            e
                        ))
                    })?;
                continue;
            }

            // An `oidc` service is an off-net identity provider. Like `file` it has
            // no ZPR network presence (no protocol, provider, cert, or client), so it
            // takes the same early-out shape; unlike `file` it carries an OidcConfig
            // and may name an on-net JWKS proxy service to weave a rule for.
            if ts_api == zpl::TS_API_OIDC {
                self.add_oidc_trusted_service(
                    config,
                    &ts_name,
                    ts_returns_attrs,
                    expiration_seconds,
                )?;
                continue;
            }

            // A `zpr-attr/1` attribute service is off-net too (reached over
            // ordinary IP; `service` is reserved), so it takes the same
            // early-out shape and carries an AttrQueryConfig.
            if ts_api == zpl::TS_API_ATTR_QUERY {
                self.add_attr_query_trusted_service(
                    config,
                    &ts_name,
                    ts_returns_attrs,
                    expiration_seconds,
                )?;
                continue;
            }

            // The config parser rejects every other API.
            return Err(CompilationError::BuildError(format!(
                "trusted service {ts_name} has unsupported api {ts_api}"
            )));
        }
        Ok(())
    }

    /// Weave an `api = "oidc"` trusted service (zipline#6).
    ///
    /// The provider is off-net, so the woven service has the file-style shape:
    /// the VS `cn == vs.zpr` as sole provider attribute, no protocol, and an
    /// `OidcConfig` carrying the pinned provider configuration. When the config
    /// declares a JWKS proxy `service`, the compiler also adds the
    /// visa-service access rule targeting that fabric service.
    fn add_oidc_trusted_service(
        &mut self,
        config: &ConfigApi,
        ts_name: &str,
        ts_returns_attrs: Vec<AttrMapping>,
        expiration_seconds: u32,
    ) -> Result<(), CompilationError> {
        // Identity attributes: the config parser enforces ["sub"] for oidc.
        let ts_identity_attrs =
            match config.get(&format!("/trusted_services/{ts_name}/id_attributes")) {
                Some(ConfigItem::KeySet(attrs)) => attrs,
                _ => Vec::new(),
            };

        // The optional JWKS proxy service. When declared it must exist in
        // [services.*]; the woven rule targets it.
        let proxy_service_id = match config.get(&format!("/trusted_services/{ts_name}/vs_service"))
        {
            Some(ConfigItem::StrVal(name)) => {
                if config.get(&format!("/services/{name}")).is_none() {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: service \"{name}\" is not declared in [services]"
                    )));
                }
                // The stored OidcConfig.jwks_proxy_service must equal the id the
                // policy emits for the service. set_connects/set_policies
                // canonicalize ids (spaces become underscores), so an id that
                // needs mangling would be stored under a name the VS can never
                // look up. Reject it instead of storing a dangling reference.
                if name.contains(' ') {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: service \"{name}\" contains spaces; \
                         the policy stores canonicalized service ids (spaces become underscores), \
                         so the stored proxy id would never match -- rename the [services] entry"
                    )));
                }
                // A proxy id equal to any trusted-service id would collide in the
                // fabric (trusted services are fabric services too) and fail later
                // with a confusing "duplicate trusted service" error. Diagnose the
                // collision here, where the configuration mistake is visible.
                if config.must_get_keys("/trusted_services").contains(&name) {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: service \"{name}\" collides with the id of a \
                         trusted service; the JWKS proxy must use a distinct [services] id"
                    )));
                }
                // The proxy is reached only by the visa service, so no ZPL names
                // it and init_services never weaves it. Add it here from its
                // config declaration (skipped if some ZPL did reference it).
                if !self.fabric.has_service(&name) {
                    let prot = match config.get(&format!("/services/{name}/protocol")) {
                        Some(citem @ ConfigItem::Protocol(_, _, _)) => citem.try_into_protocol()?,
                        _ => {
                            return Err(CompilationError::ConfigError(format!(
                                "protocol for service {name} not found in configuration"
                            )));
                        }
                    };
                    let provider_attrs = match config.get(&format!("/services/{name}/provider")) {
                        Some(ConfigItem::AttrList(alist)) => vec_to_attributes(&alist)?,
                        _ => {
                            return Err(CompilationError::ConfigError(format!(
                                "service {name} missing provider attributes"
                            )));
                        }
                    };
                    let resolved = self.resolve_attributes(&provider_attrs, config)?;
                    self.fabric
                        .add_service(&name, &prot, &resolved, ServiceType::Regular)?;
                }
                Some(name)
            }
            _ => None, // omitted: B1 already warned about direct egress
        };

        // An oidc trusted service has no on-net service on either side, so a
        // conventionally-named [services.<id>*] block that is not the declared
        // proxy is a configuration mistake. Fail loudly.
        for name in [
            ts_name.to_string(),
            format!("{ts_name}-vs"),
            format!("{ts_name}-client"),
        ] {
            if Some(&name) == proxy_service_id.as_ref() {
                continue;
            }
            if config.get(&format!("/services/{name}")).is_some() {
                return Err(CompilationError::ConfigError(format!(
                    "trusted_service {ts_name}: api=\"oidc\" has no on-net service; remove [services.{name}]"
                )));
            }
        }

        // Seed JWKS: read relative to the .zplc directory, require a JSON
        // document with a top-level `keys` array, and embed it verbatim.
        let oidc_cfg = config.get_oidc_ts_config(ts_name).ok_or_else(|| {
            CompilationError::ConfigError(format!(
                "trusted_service {ts_name}: api=\"oidc\" but no oidc configuration"
            ))
        })?;
        let seed_jwks = match &oidc_cfg.seed_jwks_path {
            Some(path) => {
                let abs_path = config.resolve_config_path(path);
                let contents = std::fs::read_to_string(&abs_path).map_err(|e| {
                    CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: failed to read seed_jwks \"{}\": {e}",
                        path.display()
                    ))
                })?;
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&contents);
                let is_jwks = parsed
                    .as_ref()
                    .map(|v| v.get("keys").is_some_and(|k| k.is_array()))
                    .unwrap_or(false);
                if !is_jwks {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: seed_jwks \"{}\" is not a JWKS document",
                        path.display()
                    )));
                }
                contents
            }
            None => String::new(), // absent -> "" on the wire
        };

        let oidc = OidcConfig {
            issuer: oidc_cfg.issuer.clone(),
            jwks_uri: oidc_cfg.jwks_uri.clone(),
            client_id: oidc_cfg.client_id.clone(),
            client_secret: oidc_cfg.client_secret.clone(),
            scopes: oidc_cfg.scopes.clone(),
            allowed_domains: oidc_cfg.allowed_domains.clone(),
            max_auth_age_seconds: oidc_cfg.max_auth_age_seconds,
            allow_offline_access: oidc_cfg.allow_offline_access,
            seed_jwks,
            jwks_proxy_service: proxy_service_id.clone(),
        };

        let vs_cn_attr = Attribute::tuple(zpl::KATTR_CN)
            .single()
            .value(zpl::VISA_SERVICE_CN)
            .build()?;
        self.fabric
            .add_trusted_service(TrustedServiceSpec {
                id: ts_name.to_string(),
                api: zpl::TS_API_OIDC.to_string(),
                provider_attrs: vec![vs_cn_attr.clone()],
                returns_attrs: ts_returns_attrs,
                identity_attrs: ts_identity_attrs,
                expiration_seconds,
                oidc: Some(oidc),
                ..Default::default()
            })
            .map_err(|e| {
                CompilationError::ConfigError(format!("error adding trusted service: {}", e))
            })?;

        // The visa service can access the JWKS proxy (if one was declared).
        if let Some(proxy_service_id) = proxy_service_id {
            let pline = PLine::new_builtin(&format!(
                "allow visa service access to trusted service {}",
                ts_name
            ));
            self.fabric.add_condition_to_service(
                false,
                &proxy_service_id,
                &[vs_cn_attr],
                &[],
                &[], // no link constraints on the trusted service policy
                true,
                None,
                &pline,
            )?;
        }
        Ok(())
    }

    /// Weave an `api = "zpr-attr/1"` trusted service (zipline#76).
    ///
    /// The attribute service is off-net (reached over ordinary IP; `service`
    /// is reserved), so the woven service has the file-style shape: the VS
    /// `cn == vs.zpr` as sole provider attribute, no protocol, and an
    /// `AttrQueryConfig` carrying the pinned service configuration. A stray
    /// conventionally-named [services.*] block is rejected as for oidc.
    fn add_attr_query_trusted_service(
        &mut self,
        config: &ConfigApi,
        ts_name: &str,
        ts_returns_attrs: Vec<AttrMapping>,
        expiration_seconds: u32,
    ) -> Result<(), CompilationError> {
        // An attribute service has no on-net service on either side, so a
        // conventionally-named [services.<id>*] block is a configuration
        // mistake. Fail loudly.
        for name in [
            ts_name.to_string(),
            format!("{ts_name}-vs"),
            format!("{ts_name}-client"),
        ] {
            if config.get(&format!("/services/{name}")).is_some() {
                return Err(CompilationError::ConfigError(format!(
                    "trusted_service {ts_name}: api=\"{}\" has no on-net service; remove [services.{name}]",
                    zpl::TS_API_ATTR_QUERY
                )));
            }
        }

        let aq_cfg = config.get_attr_query_ts_config(ts_name).ok_or_else(|| {
            CompilationError::ConfigError(format!(
                "trusted_service {ts_name}: api=\"{}\" but no attr_query configuration",
                zpl::TS_API_ATTR_QUERY
            ))
        })?;

        // CA pin: read relative to the .zplc directory, parse the complete PEM
        // bundle requiring at least one valid certificate (PR #8 review: a
        // marker-only check let truncated PEM through to break the VS trust
        // store at runtime), then embed the PEM contents verbatim so the pin
        // is signed with the policy. "" on the wire means system roots.
        let ca_cert_pem = match &aq_cfg.ca_cert_path {
            Some(path) => {
                let abs_path = config.resolve_config_path(path);
                let contents = std::fs::read_to_string(&abs_path).map_err(|e| {
                    CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: failed to read ca_cert_path \"{}\": {e}",
                        path.display()
                    ))
                })?;
                let certs = openssl::x509::X509::stack_from_pem(contents.as_bytes())
                    .map_err(|e| {
                        CompilationError::ConfigError(format!(
                            "trusted_service {ts_name}: ca_cert_path \"{}\" contains no valid certificate: {e}",
                            path.display()
                        ))
                    })?;
                if certs.is_empty() {
                    return Err(CompilationError::ConfigError(format!(
                        "trusted_service {ts_name}: ca_cert_path \"{}\" contains no valid certificate",
                        path.display()
                    )));
                }
                Some(contents)
            }
            None => None,
        };

        let attr_query = AttrQueryConfig {
            url: aq_cfg.url.clone(),
            ca_cert_pem,
            timeout_seconds: aq_cfg.timeout_seconds,
        };

        let vs_cn_attr = Attribute::tuple(zpl::KATTR_CN)
            .single()
            .value(zpl::VISA_SERVICE_CN)
            .build()?;
        self.fabric
            .add_trusted_service(TrustedServiceSpec {
                id: ts_name.to_string(),
                api: zpl::TS_API_ATTR_QUERY.to_string(),
                provider_attrs: vec![vs_cn_attr],
                returns_attrs: ts_returns_attrs,
                expiration_seconds,
                attr_query: Some(attr_query),
                ..Default::default()
            })
            .map_err(|e| {
                CompilationError::ConfigError(format!("error adding trusted service: {}", e))
            })?;
        Ok(())
    }

    /// Check the details around the two components of a trusted service: the visa-facing and the
    /// actor/adapter facing.
    ///
    fn add_bootstrap_records(
        &mut self,
        config: &ConfigApi,
        ctx: &CompilationCtx,
    ) -> Result<(), CompilationError> {
        let bootstrap_cns = match config.get("zpr/bootstrap") {
            Some(ConfigItem::KeySet(cns)) => cns,
            _ => Vec::new(),
        };
        for cnval in &bootstrap_cns {
            match config.get(&format!("zpr/bootstrap/{cnval}")) {
                Some(ConfigItem::BytesB64(b64data)) => match BASE64_STANDARD.decode(b64data) {
                    Ok(cert_data) => {
                        self.fabric.push_bootstrap_record(cnval, cert_data);
                    }
                    Err(e) => {
                        return Err(CompilationError::ConfigError(format!(
                            "error decoding certificate data: {}",
                            e
                        )));
                    }
                },
                item @ Some(_) => {
                    return Err(CompilationError::ConfigError(format!(
                        "unexpected result from config: expected certificate data got {:?}",
                        item
                    )));
                }
                None => {
                    ctx.warn(&format!("no certificate for bootstrap record {}", cnval))?;
                }
            }
        }
        Ok(())
    }
}

/// Returns first service starting with `class_name` and searching ancestors that is
/// defined in our service index (ie, is in configuration).
fn find_defined_service(
    class_name: &str,
    config: &ConfigApi,
    class_idx: &HashMap<String, &Class>,
) -> Option<String> {
    let mut cur_svc_class = class_name;
    let mut matched_service = config.get(&format!("/services/{}", cur_svc_class));

    while matched_service.is_none() {
        let cl = class_idx.get(cur_svc_class).unwrap();
        if cl.parent == cl.name {
            // we are at top of hierarchy
            break;
        }
        cur_svc_class = &cl.parent;
        matched_service = config.get(&format!("/services/{}", cur_svc_class));
    }
    matched_service.map(|s| s.to_string())
}

/// Get all the WITH attributes on the named class, including any attributes on
/// the parent classes.  We ignore optional attributes.
fn attrs_for_class(
    class_idx: &HashMap<String, &Class>,
    class_name: &str,
) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    let mut cl = class_idx.get(class_name).ok_or_else(|| {
        CompilationError::BuildError(format!("class {} not found in class index", class_name))
    })?;

    // If my parent name is not my name... grab all my attributes.
    while cl.parent != cl.name {
        for a in &cl.with_attrs {
            if a.optional {
                continue;
            }
            attrs.push(a.clone());
        }
        // Then move up to the parent class.
        cl = class_idx.get(&cl.parent).ok_or_else(|| {
            CompilationError::BuildError(format!(
                "error parent class {} of {} not found",
                cl.parent, cl.name
            ))
        })?;
    }
    // WHEN parent name is my name, take my attributes
    for a in &cl.with_attrs {
        if a.optional {
            continue;
        }
        attrs.push(a.clone());
    }
    Ok(attrs)
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::context::CompilationCtx;
    use crate::lex::Token;
    use crate::ptypes::{AllowClause, ClassFlavor, Clause, FPos};
    use std::env;

    /// A weaver with a single configured link carrying the given attributes, for
    /// exercising `check_link_conditions_satisfiable` directly.
    fn weaver_with_link_attrs(attrs: Vec<Attribute>) -> Weaver {
        let mut w = Weaver::new(WeavingContext::default());
        let addr = |last: u16| NodeLinkAddr {
            zpr_addr: format!("fd5a:5052:90de::{last}").parse().unwrap(),
            substrate: Some(SubstrateAddr {
                host: "127.0.0.1".to_string(),
                port: 5000 + last,
            }),
        };
        w.fabric.push_link(FabricLink {
            link_id: "n0n1".to_string(),
            node_a: addr(1),
            node_b: addr(2),
            link_attrs: attrs,
        });
        w
    }

    fn link_tuple(name: &str, value: &str) -> Attribute {
        Attribute::tuple(name)
            .single()
            .value(value)
            .domain_hint(AttrDomain::Link)
            .build()
            .expect("failed to build link tuple attribute")
    }

    #[test]
    fn test_link_condition_unknown_attribute_is_an_error() {
        // No configured link carries `link.medium` at all -- the statement is dead code.
        let w = weaver_with_link_attrs(vec![link_tuple("location", "usa")]);
        let err = w
            .check_link_conditions_satisfiable(
                &[link_tuple("medium", "fibre")],
                &FPos::default(),
                &CompilationCtx::default(),
            )
            .expect_err("unknown link attribute must fail the compile");
        let msg = err.to_string();
        assert!(
            msg.contains("not present on any configured link"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_link_condition_unknown_value_warns() {
        // `link.location` exists, but no link carries the value `use` -- warn, do not fail.
        let w = weaver_with_link_attrs(vec![link_tuple("location", "usa")]);
        w.check_link_conditions_satisfiable(
            &[link_tuple("location", "use")],
            &FPos::default(),
            &CompilationCtx::default(),
        )
        .expect("an unknown link attribute value must warn, not fail");

        // With werror the same warning becomes an error, which lets us assert its text.
        let err = w
            .check_link_conditions_satisfiable(
                &[link_tuple("location", "use")],
                &FPos::default(),
                &CompilationCtx::new(false, true),
            )
            .expect_err("werror must promote the unknown-value warning to an error");
        let msg = err.to_string();
        assert!(
            msg.contains("link.location"),
            "warning should name the attribute: {msg}"
        );
        assert!(
            msg.contains("'use'"),
            "warning should name the offending value: {msg}"
        );
        assert!(
            msg.contains("usa"),
            "warning should list the configured values: {msg}"
        );
    }

    #[test]
    fn test_link_condition_known_value_is_silent() {
        // Exact match on both key and value: no error, and werror proves no warning fired.
        let w = weaver_with_link_attrs(vec![link_tuple("location", "usa")]);
        w.check_link_conditions_satisfiable(
            &[link_tuple("location", "usa")],
            &FPos::default(),
            &CompilationCtx::new(false, true),
        )
        .expect("a link condition matching a configured value must not warn");
    }

    #[test]
    fn test_link_condition_tag_has_no_value_check() {
        // Tags carry no value, so only the key check applies. werror would surface any
        // spurious value warning as an error.
        let tag = |name: &str| {
            Attribute::tag(name)
                .domain_hint(AttrDomain::Link)
                .build()
                .expect("failed to build link tag attribute")
        };
        let w = weaver_with_link_attrs(vec![tag("secure")]);
        w.check_link_conditions_satisfiable(
            &[tag("secure")],
            &FPos::default(),
            &CompilationCtx::new(false, true),
        )
        .expect("a configured link tag must satisfy the same tag in an over clause");
    }

    #[test]
    fn test_init_services_minimal() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["foo", "fee"]]

        [visa_service]
        dock_node = "n0"
        "#;

        let mut w = Weaver::new(WeavingContext::default());
        let class_idx = HashMap::new();
        let policy = Policy::default();
        let config =
            ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &CompilationCtx::default())
                .expect("failed to parse config");

        let res = w.init_services(&class_idx, &policy, &config);
        assert!(res.is_ok());

        // Should create two services: visa-service and visa-service-admin
        assert_eq!(w.fabric.services.len(), 2);

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
        assert!(vs.is_some());

        let vs = w
            .fabric
            .services
            .iter()
            .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
        assert!(vs.is_some());
    }

    #[test]
    fn test_init_services_must_be_in_zpl() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [protocols.fee]
        l4protocol = "iana.TCP"
        port = 80

        [services.foo]
        protocol = "fee"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [services.bar]
        protocol = "fee"
        "#;

        let mut class_idx = HashMap::new();
        let mut policy = Policy::default();
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        {
            let mut w = Weaver::new(WeavingContext::default());

            let res = w.init_services(&class_idx, &policy, &config);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());

            // Should create two services: visa-service and visa-service-admin.
            // Does not create services just because they are in the config.
            assert_eq!(w.fabric.services.len(), 2);
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == zpl::VS_SERVICE_NAME);
            assert!(vs.is_some());
            let vs = w
                .fabric
                .services
                .iter()
                .find(|s| s.fabric_id == format!("{}/admin", zpl::VS_SERVICE_NAME));
            assert!(vs.is_some());
        }

        // But will create services if they are in the ZPL.

        // We are only calling init_services which does not create policies anyway.
        // Will only notice that the 'foo' service is referenced.
        let a_foo = AllowClause {
            clause_id: 1,
            span: (FPos::default(), FPos::default()),
            client: vec![
                Clause::new(ClassFlavor::Device, "device", Token::default()),
                Clause::new(ClassFlavor::User, "user", Token::default()),
            ],
            server: vec![Clause::new(ClassFlavor::Service, "foo", Token::default())],
            link: None,
            signal: None,
        };
        policy.allows.push(a_foo);

        // Class named "foo" must have been parsed.
        let defaults = Class::defaults();
        for def_cl in &defaults {
            class_idx.insert(def_cl.name.clone(), def_cl);
        }
        let foo_cls = Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: "foo".to_string(),
            aka: None,
            plural: "foos".to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: true,
            class_id: 100,
        };
        class_idx.insert("foo".to_string(), &foo_cls);

        {
            let mut w = Weaver::new(WeavingContext::default());
            let res = w.init_services(&class_idx, &policy, &config);
            println!("{:?}", res);
            assert!(res.is_ok(), "init_services failed: {}", res.unwrap_err());
            assert_eq!(w.fabric.services.len(), 3);
            let vs = w.fabric.services.iter().find(|s| s.fabric_id == "foo");
            assert!(vs.is_some());
        }
    }

    #[test]
    fn test_reads_return_and_id_attrs() {
        let cfg = r#"
        [nodes.n0]
        key = "none"
        zpr_address = "fd5a:5052:90de::1"
        interfaces = [ "in1" ]
        in1.netaddr = "127.0.0.1:5000"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [visa_service]
        dock_node = "n0"

        [trusted_services.idp]
        api = "oidc"
        issuer = "https://idp.example.com"
        jwks_uri = "https://idp.example.com/jwks"
        client_id = "zpr-client"
        allowed_domains = ["*"]
        expiration_seconds = 3600
        returns_attributes = ["sub -> user.id", "email -> user.email"]
        identity_attributes = ["sub"]
        "#;

        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut wctx = WeavingContext::default();
        wctx.add_used_trusted_service("idp");

        let mut w = Weaver::new(wctx);
        let res = w.add_trusted_services(&config, &ctx);
        assert!(
            res.is_ok(),
            "add_trusted_services failed: {}",
            res.unwrap_err()
        );

        // Will create the trusted service.
        assert_eq!(w.fabric.services.len(), 1);

        let fsvc = &w.fabric.services[0];
        assert_eq!(fsvc.fabric_id, "idp");
        let ts = fsvc.trusted_service.as_ref().unwrap();
        let return_attrs = &ts.returns_attrs;
        assert_eq!(return_attrs.len(), 2);
        let spec = |k: &str| {
            return_attrs
                .iter()
                .find(|m| m.service_attr_key == k)
                .unwrap()
                .attr
                .to_schema_string()
        };
        assert_eq!(spec("sub"), "user.id");
        assert_eq!(spec("email"), "user.email");
        let id_attrs = &ts.identity_attrs;
        assert_eq!(id_attrs.len(), 1);
        assert!(id_attrs.contains(&String::from("sub")));
    }

    #[test]
    fn test_resolve_attributes_rejects_zpr_addr() {
        // zipline#109: zpr.addr is no longer resolvable as a provider attribute.
        // Only the node emitter (init_nodes) constructs it, AFTER resolution, from
        // the node's zpr_address; nothing authored reaches resolve_attributes with
        // it, and if something does it must fail like any other unvouched attribute.
        let cfg = r#"
        [nodes.n0]
        zpr_address = "fd5a:5052:90de::1"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [trusted_services.attrs]
        api = "file"
        returns_attributes = ["id -> user.id"]
        "#;

        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(&cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut w = Weaver::new(WeavingContext::default());
        let addr = Attribute::try_zpr_internal_attr(zpl::KATTR_ADDR, "fd5a:5052:8888::8")
            .expect("failed to build zpr.addr attribute");

        let err = w
            .resolve_attributes(&[addr], &config)
            .expect_err("zpr.addr must not resolve through any trusted service");
        assert!(
            err.to_string().contains("not found in any trusted service"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_file_trusted_service_used_only() {
        // Two file services; only one is referenced by the (simulated) ZPL.
        let cfg = r#"
        [nodes.n0]
        zpr_address = "fd5a:5052:90de::1"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [trusted_services.used_fs]
        api = "file"
        returns_attributes = ["a -> user.usedattr"]

        [trusted_services.unused_fs]
        api = "file"
        returns_attributes = ["b -> user.unusedattr"]
        "#;
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut w = Weaver::new(WeavingContext::default());

        // Referencing user.usedattr marks only used_fs as in-use.
        let attr = Attribute::tuple("user.usedattr")
            .single()
            .value("x")
            .build()
            .unwrap();
        let resolved = w
            .resolve_attributes(&[attr], &config)
            .expect("attr should resolve");
        assert_eq!(resolved.len(), 1);
        assert!(w.wctx.used_trusted_services.contains("used_fs"));
        assert!(!w.wctx.used_trusted_services.contains("unused_fs"));

        // Only the used file service is woven into the fabric; the unused one is dropped.
        w.add_trusted_services(&config, &ctx)
            .expect("add_trusted_services");
        let trusted: Vec<&str> = w
            .fabric
            .services
            .iter()
            .filter(|s| matches!(s.service_type, ServiceType::Trusted(_)))
            .map(|s| s.fabric_id.as_str())
            .collect();
        assert_eq!(trusted, vec!["used_fs"]);
    }

    #[test]
    fn test_trusted_service_transitive_use() {
        // `outer` is referenced directly; the provider attribute of its JWKS proxy
        // service is vouched for by `inner`, so `inner` must be discovered
        // transitively and woven too.
        let cfg = r#"
        [nodes.n0]
        zpr_address = "fd5a:5052:90de::1"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [trusted_services.inner]
        api = "file"
        returns_attributes = ["ia -> user.innerattr"]

        [trusted_services.outer]
        api = "oidc"
        issuer = "https://idp.example.com"
        jwks_uri = "https://idp.example.com/jwks"
        client_id = "zpr-client"
        allowed_domains = ["*"]
        expiration_seconds = 3600
        service = "outer-jwks-proxy"
        returns_attributes = ["sub -> user.sub", "oa -> user.outerattr"]
        identity_attributes = ["sub"]

        [protocols.tcp]
        l4protocol = "TCP"
        port = 3128

        [services.outer-jwks-proxy]
        protocol = "tcp"
        port = 3128
        provider = [["user.innerattr", "someval"]]
        "#;
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut w = Weaver::new(WeavingContext::default());
        // Reference an attribute only `outer` provides.
        let attr = Attribute::tuple("user.outerattr")
            .single()
            .value("y")
            .build()
            .unwrap();
        w.resolve_attributes(&[attr], &config)
            .expect("attr should resolve");
        assert!(w.wctx.used_trusted_services.contains("outer"));
        assert!(!w.wctx.used_trusted_services.contains("inner"));

        // Weaving discovers `inner` transitively through `outer`'s proxy provider attribute.
        w.add_trusted_services(&config, &ctx)
            .expect("add_trusted_services");
        let mut trusted: Vec<&str> = w
            .fabric
            .services
            .iter()
            .filter(|s| matches!(s.service_type, ServiceType::Trusted(_)))
            .map(|s| s.fabric_id.as_str())
            .collect();
        trusted.sort();
        assert_eq!(trusted, vec!["inner", "outer"]);
    }

    #[test]
    fn test_identity_vendor_never_pruned() {
        // `google` vends identity attributes (`identity_attributes = ["sub"]`), so it is
        // a query key for every attribute store in the policy -- `happyfile`'s JSON is
        // keyed by identity attribute and value. Nothing in the (simulated) ZPL
        // references google's returned attributes, yet it must still be woven;
        // only non-identity-vending services are pruned when unreferenced.
        let cfg = r#"
        [nodes.n0]
        zpr_address = "fd5a:5052:90de::1"
        provider = [["device.zpr.adapter.cn", "fee"]]

        [trusted_services.happyfile]
        api = "file"
        returns_attributes = ["hair_color -> user.hair_color", "lazy -> #user.lazy"]
        expiration_seconds = 3600

        [trusted_services.google]
        api = "oidc"
        issuer = "https://accounts.google.com"
        jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
        client_id = "1234567890-abcdef.apps.googleusercontent.com"
        allowed_domains = ["*"]
        expiration_seconds = 3600
        returns_attributes = ["sub -> user.sub", "email -> user.email"]
        identity_attributes = ["sub"]
        "#;
        let ctx = CompilationCtx::default();
        let config = ConfigApi::new_from_toml_content(cfg, &env::temp_dir(), &ctx)
            .expect("failed to parse config");

        let mut w = Weaver::new(WeavingContext::default());

        // Reference only the file service's attribute: google stays unmarked.
        let attr = Attribute::tuple("user.hair_color")
            .single()
            .value("red")
            .build()
            .unwrap();
        w.resolve_attributes(&[attr], &config)
            .expect("attr should resolve");
        assert!(w.wctx.used_trusted_services.contains("happyfile"));
        assert!(!w.wctx.used_trusted_services.contains("google"));

        // Weaving must retain the identity vendor even though ZPL never
        // references user.sub or user.email.
        w.add_trusted_services(&config, &ctx)
            .expect("add_trusted_services");
        let mut trusted: Vec<&str> = w
            .fabric
            .services
            .iter()
            .filter(|s| matches!(s.service_type, ServiceType::Trusted(_)))
            .map(|s| s.fabric_id.as_str())
            .collect();
        trusted.sort();
        assert_eq!(trusted, vec!["google", "happyfile"]);
    }
}
