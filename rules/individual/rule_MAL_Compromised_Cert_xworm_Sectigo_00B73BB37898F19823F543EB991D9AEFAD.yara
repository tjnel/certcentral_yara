import "pe"

rule MAL_Compromised_Cert_xworm_Sectigo_00B73BB37898F19823F543EB991D9AEFAD {
   meta:
      description         = "Detects xworm with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-04"
      version             = "1.0"

      hash                = "4b73f071b37da9dc75fc66c196d7aabc2788ecde9041972d0a9599afdd7321c6"
      malware             = "xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nextgensoftware Company Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:b7:3b:b3:78:98:f1:98:23:f5:43:eb:99:1d:9a:ef:ad"
      cert_thumbprint     = "EC90F0D8C878081D9362937124E56BCE10DE97BC"
      cert_valid_from     = "2025-02-04"
      cert_valid_to       = "2026-02-04"

      country             = "VN"
      state               = "Ho Chi Minh"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "0318797820"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:b7:3b:b3:78:98:f1:98:23:f5:43:eb:99:1d:9a:ef:ad"
      )
}
