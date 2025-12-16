import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_71548998D5724DFE7ADF6F62 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-01"
      version             = "1.0"

      hash                = "2dc04e9bd4a569f4d3bd1fc5de071ec63eab97745d04b3c9e6e69fafc4191f74"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Vtorsintez"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "71:54:89:98:d5:72:4d:fe:7a:df:6f:62"
      cert_thumbprint     = "86421DFFD1593A53774B764A9926D17FB74DCCA7"
      cert_valid_from     = "2025-05-01"
      cert_valid_to       = "2026-05-02"

      country             = "RU"
      state               = "Moscow Oblast"
      locality            = "Chekhov"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "71:54:89:98:d5:72:4d:fe:7a:df:6f:62"
      )
}
