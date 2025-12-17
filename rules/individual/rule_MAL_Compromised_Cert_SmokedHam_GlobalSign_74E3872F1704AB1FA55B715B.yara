import "pe"

rule MAL_Compromised_Cert_SmokedHam_GlobalSign_74E3872F1704AB1FA55B715B {
   meta:
      description         = "Detects SmokedHam with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "cab3047a253eb1bef57d4cc2318ca840b3e40658265609291d98cf42092b2416"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai GAIN STARS Trading Company Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "74:e3:87:2f:17:04:ab:1f:a5:5b:71:5b"
      cert_thumbprint     = "0C57941579689D70233E8872BED60C11412903A3"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-18"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310115667837474D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "74:e3:87:2f:17:04:ab:1f:a5:5b:71:5b"
      )
}
