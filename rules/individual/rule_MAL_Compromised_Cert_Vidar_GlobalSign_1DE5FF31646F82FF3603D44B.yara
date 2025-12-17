import "pe"

rule MAL_Compromised_Cert_Vidar_GlobalSign_1DE5FF31646F82FF3603D44B {
   meta:
      description         = "Detects Vidar with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-19"
      version             = "1.0"

      hash                = "645792d4d009f52135a1e760e45d440dbdf2e283f5ad33b949b894ada8d0d602"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Webber Air Investments LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:e5:ff:31:64:6f:82:ff:36:03:d4:4b"
      cert_thumbprint     = "5458C95F64BC96AEA8614EABA89D587C49BDAD03"
      cert_valid_from     = "2025-02-19"
      cert_valid_to       = "2026-02-20"

      country             = "US"
      state               = "Alaska"
      locality            = "Ketchikan"
      email               = "???"
      rdn_serial_number   = "10076154"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:e5:ff:31:64:6f:82:ff:36:03:d4:4b"
      )
}
