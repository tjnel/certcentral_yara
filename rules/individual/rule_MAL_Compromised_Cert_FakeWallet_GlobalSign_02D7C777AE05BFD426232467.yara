import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_02D7C777AE05BFD426232467 {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "879b1e4a67af31ad11e210d03d43ccd5f0a6b981fb6a4d87e1ee360a7ad845f0"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ENRRICHONE WELL-BEING PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:d7:c7:77:ae:05:bf:d4:26:23:24:67"
      cert_thumbprint     = "B0727D22C094A131381D32FE93416C562D5208F4"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2026-06-04"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "mahaveerenrrichone2@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:d7:c7:77:ae:05:bf:d4:26:23:24:67"
      )
}
