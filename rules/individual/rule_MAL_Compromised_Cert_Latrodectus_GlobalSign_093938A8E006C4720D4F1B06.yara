import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_093938A8E006C4720D4F1B06 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-18"
      version             = "1.0"

      hash                = "dea85c1e75be9db2c7c96007283389ddf28a21d79a05f3e6396a0c7f780b7b9f"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LINDHOLM SOLUTIONS L.P."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "09:39:38:a8:e0:06:c4:72:0d:4f:1b:06"
      cert_thumbprint     = "7CBAA1A3646AD7244167AC210FCF481BF74B24CD"
      cert_valid_from     = "2025-08-18"
      cert_valid_to       = "2026-08-19"

      country             = "GB"
      state               = "Scotland"
      locality            = "Glasgow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "09:39:38:a8:e0:06:c4:72:0d:4f:1b:06"
      )
}
