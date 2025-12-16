import "pe"

rule MAL_Compromised_Cert_FakeKeePass_GlobalSign_3ACEAA7BDFAB12376A840610 {
   meta:
      description         = "Detects FakeKeePass with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-02"
      version             = "1.0"

      hash                = "9fa3042b3f6ae325c56e9180705f29a614b99c5005ef7acf671413422b20836f"
      malware             = "FakeKeePass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Paster"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3a:ce:aa:7b:df:ab:12:37:6a:84:06:10"
      cert_thumbprint     = "A810A1D6C82871D12BD27297EA28A0330F4D7AD6"
      cert_valid_from     = "2025-07-02"
      cert_valid_to       = "2026-07-03"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:ce:aa:7b:df:ab:12:37:6a:84:06:10"
      )
}
