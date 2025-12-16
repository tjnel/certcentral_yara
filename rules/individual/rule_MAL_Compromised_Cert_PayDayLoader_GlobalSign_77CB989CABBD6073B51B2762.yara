import "pe"

rule MAL_Compromised_Cert_PayDayLoader_GlobalSign_77CB989CABBD6073B51B2762 {
   meta:
      description         = "Detects PayDayLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-27"
      version             = "1.0"

      hash                = "b5151e75e8e8af1519bef9111f2acbb24b290f0b1f9e7bc0518e9e6eac95f7cc"
      malware             = "PayDayLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AKE Holdings Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "77:cb:98:9c:ab:bd:60:73:b5:1b:27:62"
      cert_thumbprint     = "FA33055AB8C304B4FDED16D55A28DFBF0DFB9992"
      cert_valid_from     = "2025-01-27"
      cert_valid_to       = "2026-01-28"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310000051291784T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "77:cb:98:9c:ab:bd:60:73:b5:1b:27:62"
      )
}
