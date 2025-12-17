import "pe"

rule MAL_Compromised_Cert_AsyncRAT_GlobalSign_46DD87B21B58C57F71E8F95F {
   meta:
      description         = "Detects AsyncRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-23"
      version             = "1.0"

      hash                = "6cb1a58a42a1520c1c899e346302c552a8559209084d25d8cdb42cdaec1223ad"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LOUNGE LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:dd:87:b2:1b:58:c5:7f:71:e8:f9:5f"
      cert_thumbprint     = "C7BFAEF38FF74EDBEA0BF718B13B26AAC34C2E74"
      cert_valid_from     = "2025-03-23"
      cert_valid_to       = "2026-02-28"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700674198"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:dd:87:b2:1b:58:c5:7f:71:e8:f9:5f"
      )
}
