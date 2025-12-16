import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_113FB829E69DBFBC6581AD49 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-17"
      version             = "1.0"

      hash                = "74c9175036bcaa239f433a98606df3a3be60ab9246f2067f500cea4b2be09a8f"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Stroytorg"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "11:3f:b8:29:e6:9d:bf:bc:65:81:ad:49"
      cert_thumbprint     = "17E9E652B7EC3D4BBB726CDA4B8EE0E3490936B2"
      cert_valid_from     = "2025-06-17"
      cert_valid_to       = "2026-06-18"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "11:3f:b8:29:e6:9d:bf:bc:65:81:ad:49"
      )
}
