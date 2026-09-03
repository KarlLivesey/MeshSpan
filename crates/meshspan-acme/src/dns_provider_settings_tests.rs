// SPDX-License-Identifier: GPL-2.0-only

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{
    CloudflareDnsSettings, DnsProviderSettings, DnsProviderSettingsError, Rfc2136DnsSettings,
    Rfc2136TsigAlgorithm, WebhookDnsSettings,
};

#[test]
fn every_provider_round_trips_exact_bounded_settings() -> Result<(), Box<dyn std::error::Error>> {
    let rfc2136 = DnsProviderSettings::Rfc2136(Rfc2136DnsSettings::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        "example.test".to_owned(),
        "meshspan-key.example.test".to_owned(),
        Rfc2136TsigAlgorithm::HmacSha256,
        vec![1; 32],
    )?);
    let cloudflare = DnsProviderSettings::Cloudflare(CloudflareDnsSettings::new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        b"cloudflare-token-value".to_vec(),
    )?);
    let webhook = DnsProviderSettings::Webhook(WebhookDnsSettings::new(
        "https://dns.example.test/meshspan".to_owned(),
        b"webhook-bearer-token".to_vec(),
    )?);

    assert_rfc2136(DnsProviderSettings::decode(&rfc2136.encode()?)?)?;
    assert_cloudflare(DnsProviderSettings::decode(&cloudflare.encode()?)?)?;
    assert_webhook(DnsProviderSettings::decode(&webhook.encode()?)?)?;
    Ok(())
}

#[test]
fn malformed_unknown_trailing_and_unsafe_values_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = DnsProviderSettings::Cloudflare(CloudflareDnsSettings::new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        b"cloudflare-token-value".to_vec(),
    )?);
    let mut trailing = settings.encode()?;
    trailing.push(0);
    assert!(matches!(
        DnsProviderSettings::decode(&trailing),
        Err(DnsProviderSettingsError::InvalidEncoding)
    ));
    assert!(matches!(
        WebhookDnsSettings::new("http://insecure.test".to_owned(), vec![1; 32]),
        Err(DnsProviderSettingsError::InvalidInput)
    ));
    assert!(matches!(
        WebhookDnsSettings::new("https://?missing-host".to_owned(), vec![b'a'; 32]),
        Err(DnsProviderSettingsError::InvalidInput)
    ));
    assert!(matches!(
        WebhookDnsSettings::new(
            "https://valid.example.test/hook".to_owned(),
            b"invalid bearer token with spaces".to_vec(),
        ),
        Err(DnsProviderSettingsError::InvalidInput)
    ));
    assert!(matches!(
        Rfc2136DnsSettings::new(
            "127.0.0.1:53".parse()?,
            "-invalid.example".to_owned(),
            "key.example".to_owned(),
            Rfc2136TsigAlgorithm::HmacSha512,
            vec![1; 32],
        ),
        Err(DnsProviderSettingsError::InvalidInput)
    ));
    Ok(())
}

fn assert_rfc2136(settings: DnsProviderSettings) -> Result<(), &'static str> {
    let DnsProviderSettings::Rfc2136(settings) = settings else {
        return Err("wrong provider variant");
    };
    assert_eq!(
        settings.server(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)
    );
    assert_eq!(settings.zone(), "example.test");
    assert_eq!(settings.key_name(), "meshspan-key.example.test");
    assert_eq!(settings.algorithm(), Rfc2136TsigAlgorithm::HmacSha256);
    assert_eq!(settings.secret(), &[1; 32]);
    Ok(())
}

fn assert_cloudflare(settings: DnsProviderSettings) -> Result<(), &'static str> {
    let DnsProviderSettings::Cloudflare(settings) = settings else {
        return Err("wrong provider variant");
    };
    assert_eq!(settings.zone_id(), "0123456789abcdef0123456789abcdef");
    assert_eq!(settings.api_token(), b"cloudflare-token-value");
    Ok(())
}

fn assert_webhook(settings: DnsProviderSettings) -> Result<(), &'static str> {
    let DnsProviderSettings::Webhook(settings) = settings else {
        return Err("wrong provider variant");
    };
    assert_eq!(settings.endpoint(), "https://dns.example.test/meshspan");
    assert_eq!(settings.bearer_token(), b"webhook-bearer-token");
    Ok(())
}
