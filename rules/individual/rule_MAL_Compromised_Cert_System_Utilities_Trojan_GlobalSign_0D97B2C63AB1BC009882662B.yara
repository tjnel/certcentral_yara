import "pe"

rule MAL_Compromised_Cert_System_Utilities_Trojan_GlobalSign_0D97B2C63AB1BC009882662B {
   meta:
      description         = "Detects System Utilities Trojan with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-24"
      version             = "1.0"

      hash                = "bf3c0ed9b5b1556390c0aed77796dc4f0392103bbdf91303f0a149619b5786a6"
      malware             = "System Utilities Trojan"
      malware_type        = "Backdoor"
      malware_notes       = "The malware exhibits the same behavior as anyPDF: https://rifteyy.org/report/system-utilities-malware-analysis"

      signer              = "Centaurus Media Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0d:97:b2:c6:3a:b1:bc:00:98:82:66:2b"
      cert_thumbprint     = "C4062D4A100EAEB57D624B1F4C2D8201C1CB6FD9"
      cert_valid_from     = "2025-07-24"
      cert_valid_to       = "2028-08-23"

      country             = "GB"
      state               = "Surrey"
      locality            = "Egham"
      email               = "mail@centaurus-media.com"
      rdn_serial_number   = "12984436"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0d:97:b2:c6:3a:b1:bc:00:98:82:66:2b"
      )
}
