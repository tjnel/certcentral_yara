import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_34AABED10099B75AD5C66580 {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-09"
      version             = "1.0"

      hash                = "4e8dcef6a5c8c44a2910d0dc0b300f4d88ee5d4c71c9e5a710564062ca1c5f9f"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Torgovyi Dom Energia"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "34:aa:be:d1:00:99:b7:5a:d5:c6:65:80"
      cert_thumbprint     = "7EB16B979B013FBC4FD343342E533492B8CB6AF6"
      cert_valid_from     = "2025-05-09"
      cert_valid_to       = "2026-05-10"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "5177746130942"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "34:aa:be:d1:00:99:b7:5a:d5:c6:65:80"
      )
}
