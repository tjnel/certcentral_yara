import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_4E13389A39911B3E1D34A95E {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "701e417355a8aa5091aaa2821ae870c8487ed3d3754095f9881a4e775e3f87af"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC KARAPUZ Publishing house"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4e:13:38:9a:39:91:1b:3e:1d:34:a9:5e"
      cert_thumbprint     = "5E13F6FFCF2E79EC70801D5DA0B94531406E020C"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-26"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4e:13:38:9a:39:91:1b:3e:1d:34:a9:5e"
      )
}
