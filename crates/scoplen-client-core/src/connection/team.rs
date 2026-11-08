// SPDX-License-Identifier: Apache-2.0
//! Resolve Organization SSH exclusively from one complete authorized inventory snapshot.

use std::collections::{BTreeMap, HashSet};

use scoplen_api::inventory::InventoryFields;
use scoplen_model::Object;
use uuid::Uuid;

use super::{
    ConnectionPlan, ConnectionRoute, CredentialMaterial, HostKeyAssessment, HostKeyPresentation,
    HostKeyStatus, HostKeyTrustSource,
};
use crate::personal_server::{PersonalServer, TeamSshAuthority, TeamSshSource};
use crate::repository::{
    AccessProfile, Host, Provenance, Record, Route, RouteChoice, RouteKind, TrustRecord,
};
use crate::store::Store;

pub(crate) struct TeamConnectionSnapshot {
    pub source: TeamSshSource,
    pub authority: TeamSshAuthority,
    objects: BTreeMap<Uuid, Object>,
}

impl TeamConnectionSnapshot {
    pub fn load(
        store: &Store,
        personal: &PersonalServer,
        source: &TeamSshSource,
    ) -> Result<Self, String> {
        let owner = source.owner(store).map_err(|error| error.to_string())?;
        let authority = personal
            .team_ssh_authority(store, source)
            .map_err(|error| error.to_string())?
            .ok_or("Refresh this team's assets before connecting.")?;
        let identity = store
            .personal_record()
            .map_err(|_| "Team inventory is unavailable.")?
            .ok_or("The Account is unavailable.")?;
        let objects = store
            .team_ssh_snapshot(&identity, owner.organization, authority.vault, authority.revision)
            .map_err(|_| "Team inventory is unavailable.")?
            .ok_or("Refresh this team's assets before connecting.")?;
        let mut snapshot = Self { source: source.clone(), authority, objects: BTreeMap::new() };
        for object in objects {
            if object.is_tombstoned() {
                continue;
            }
            InventoryFields::from_object(&object).map_err(|_| "The team inventory is invalid.")?;
            if snapshot.objects.insert(object.id, object).is_some() {
                return Err("The team inventory contains duplicate objects.".into());
            }
        }
        snapshot.current(store, personal)?;
        Ok(snapshot)
    }

    pub fn current(&self, store: &Store, personal: &PersonalServer) -> Result<(), String> {
        if personal.team_ssh_authority(store, &self.source).map_err(|error| error.to_string())?
            != Some(self.authority)
        {
            return Err("Team access changed. Refresh its assets before connecting again.".into());
        }
        Ok(())
    }

    pub fn read<R: Record>(&self, id: Uuid) -> Result<R, String> {
        let object = self.objects.get(&id)
            .filter(|object| object.object_type == R::TYPE)
            .ok_or("A required team asset is not visible. Ask an administrator to review its read permissions.")?;
        R::read(object).map_err(|_| "The team asset is invalid.".into())
    }

    pub fn plan(&self, profile_id: Uuid) -> Result<(ConnectionPlan, AccessProfile, Host), String> {
        let profile = self.read::<AccessProfile>(profile_id)?;
        let host = self.read::<Host>(profile.host)?;
        if profile.credential.is_some() {
            return Err("A team Login cannot select a Personal credential.".into());
        }
        let route = match profile.route {
            RouteChoice::Direct => ConnectionRoute::Direct,
            RouteChoice::Route(id) => match self.read::<Route>(id)?.kind {
                RouteKind::Jump { hops } => ConnectionRoute::Jump { hops },
                RouteKind::Socks5 { proxy, credential: None, username: None } => {
                    ConnectionRoute::Socks5 { proxy, credential: None, username: None }
                }
                RouteKind::HttpConnect { proxy, credential: None, username: None } => {
                    ConnectionRoute::HttpConnect { proxy, credential: None, username: None }
                }
                RouteKind::Command { command } => ConnectionRoute::Command { command },
                RouteKind::Managed { gateway_network } => {
                    ConnectionRoute::Managed { gateway_network }
                }
                _ => return Err("A team proxy cannot select a Personal credential.".into()),
            },
        };
        let plan = ConnectionPlan {
            profile_id,
            host_id: host.meta.id,
            address: host.address.clone(),
            port: host.port,
            username: profile.username.clone(),
            route,
            credential: CredentialMaterial::OrganizationCertificate,
        };
        Ok((plan, profile, host))
    }

    pub fn plans(
        &self,
        profile: Uuid,
    ) -> Result<Vec<(ConnectionPlan, AccessProfile, Host)>, String> {
        let mut target = self.plan(profile)?;
        let mut plans = Vec::new();
        if let ConnectionRoute::Jump { hops } = &target.0.route {
            if hops.is_empty() {
                return Err("The team Jump route has no Logins.".into());
            }
            let mut profiles = HashSet::from([profile]);
            let mut hosts = HashSet::from([target.0.host_id]);
            for hop in hops {
                let plan = self.plan(*hop)?;
                if !profiles.insert(plan.0.profile_id) || !hosts.insert(plan.0.host_id) {
                    return Err("The team Jump route repeats a Login or Host.".into());
                }
                if plan.0.route != ConnectionRoute::Direct {
                    return Err("Every team jump Login must use a Direct route.".into());
                }
                plans.push(plan);
            }
            target.0.route = ConnectionRoute::Direct;
        }
        plans.push(target);
        Ok(plans)
    }

    pub fn assess(
        &self,
        store: &Store,
        host: Uuid,
        key: &HostKeyPresentation,
    ) -> Result<HostKeyAssessment, String> {
        let mut changed = false;
        for object in self.objects.values().filter(|object| object.object_type == TrustRecord::TYPE)
        {
            let record =
                TrustRecord::read(object).map_err(|_| "The team trust record is invalid.")?;
            if record.host != Some(host) || record.revoked || record.ca {
                continue;
            }
            changed = true;
            if record.key.as_deref() == Some(key.key.as_str())
                && record.fingerprint.as_deref() == Some(key.fingerprint.as_str())
            {
                return Ok(HostKeyAssessment {
                    status: HostKeyStatus::Trusted,
                    review: None,
                    source: Some(HostKeyTrustSource {
                        device_id: record.accepted_by_device.map(|id| id.to_string()),
                        device_name: None,
                        accepted_at: record.accepted_at.map(|time| time.to_string()),
                        imported: record.provenance == Some(Provenance::Imported),
                        current: record.accepted_by_device == Some(store.device_id()),
                    }),
                });
            }
        }
        if let Some(saved) = store
            .team_host_trust(&self.source, host)
            .map_err(|_| "Team Host trust is unavailable.")?
        {
            changed = true;
            if saved.key == key.key && saved.fingerprint == key.fingerprint {
                return Ok(HostKeyAssessment {
                    status: HostKeyStatus::Trusted,
                    review: None,
                    source: Some(HostKeyTrustSource {
                        device_id: Some(self.source.device_id.clone()),
                        device_name: None,
                        accepted_at: Some(saved.accepted_at.to_string()),
                        imported: false,
                        current: true,
                    }),
                });
            }
        }
        Ok(HostKeyAssessment {
            status: if changed { HostKeyStatus::Changed } else { HostKeyStatus::New },
            source: None,
            review: None,
        })
    }
}

#[cfg(test)]
mod tests;
