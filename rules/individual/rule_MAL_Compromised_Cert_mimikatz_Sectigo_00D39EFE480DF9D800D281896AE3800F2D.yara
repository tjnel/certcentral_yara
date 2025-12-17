import "pe"

rule MAL_Compromised_Cert_mimikatz_Sectigo_00D39EFE480DF9D800D281896AE3800F2D {
   meta:
      description         = "Detects mimikatz with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-04"
      version             = "1.0"

      hash                = "f20e0114c8038b9d66bd45049c9396254586f307390479746a6c67f5e1abce2d"
      malware             = "mimikatz"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "McDonald's Corporation"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:d3:9e:fe:48:0d:f9:d8:00:d2:81:89:6a:e3:80:0f:2d"
      cert_thumbprint     = "22EACBF575EA3FF19A6F639E80E8768405C9BDFE"
      cert_valid_from     = "2024-06-04"
      cert_valid_to       = "2025-06-04"

      country             = "US"
      state               = "Illinois"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:d3:9e:fe:48:0d:f9:d8:00:d2:81:89:6a:e3:80:0f:2d"
      )
}
