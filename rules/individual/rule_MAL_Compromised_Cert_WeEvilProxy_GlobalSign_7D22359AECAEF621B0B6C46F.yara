import "pe"

rule MAL_Compromised_Cert_WeEvilProxy_GlobalSign_7D22359AECAEF621B0B6C46F {
   meta:
      description         = "Detects WeEvilProxy with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-30"
      version             = "1.0"

      hash                = "e645e195517a817473a01ed82488e5148c60abd02d83dc097df0b00195f85936"
      malware             = "WeEvilProxy"
      malware_type        = "Infostealer"
      malware_notes       = "This malware primarily targets cryptocurrencies. It is distributed through advertisements targing crypto users: https://labs.withsecure.com/publications/weevilproxy"

      signer              = "LLC Stroy Project 77"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7d:22:35:9a:ec:ae:f6:21:b0:b6:c4:6f"
      cert_thumbprint     = "58118FD44069DC5D54E0C46914982F198EDF5F72"
      cert_valid_from     = "2025-06-30"
      cert_valid_to       = "2026-07-01"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7d:22:35:9a:ec:ae:f6:21:b0:b6:c4:6f"
      )
}
