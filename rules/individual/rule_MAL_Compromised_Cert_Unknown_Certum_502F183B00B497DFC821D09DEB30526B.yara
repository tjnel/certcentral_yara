import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_502F183B00B497DFC821D09DEB30526B {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-26"
      version             = "1.0"

      hash                = "24a26ac9cd209bf84831dae7d778fceb46b1e30b48454c130a6e62accdc1369e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "T H SUPPORT SERVICES LTD"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "50:2f:18:3b:00:b4:97:df:c8:21:d0:9d:eb:30:52:6b"
      cert_thumbprint     = "21297766029D043DFBA740CD5203E45171FC8EAA"
      cert_valid_from     = "2024-11-26"
      cert_valid_to       = "2025-11-26"

      country             = "GB"
      state               = "Greater Manchester"
      locality            = "Stretford"
      email               = "???"
      rdn_serial_number   = "07890919"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "50:2f:18:3b:00:b4:97:df:c8:21:d0:9d:eb:30:52:6b"
      )
}
