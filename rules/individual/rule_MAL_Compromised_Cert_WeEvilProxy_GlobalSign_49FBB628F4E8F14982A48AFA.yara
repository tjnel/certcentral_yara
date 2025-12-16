import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_49FBB628F4E8F14982A48AFA {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "58ffc7ad61b7d8038b45e1e2162b98d7e011b29fec1601068a98f6a272611b3e"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC MIR RTI"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:fb:b6:28:f4:e8:f1:49:82:a4:8a:fa"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2026-04-16"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:fb:b6:28:f4:e8:f1:49:82:a4:8a:fa"
      )
}
