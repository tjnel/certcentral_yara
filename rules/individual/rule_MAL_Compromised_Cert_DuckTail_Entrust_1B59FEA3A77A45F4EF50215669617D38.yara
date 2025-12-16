import "pe"

rule MAL_Compromised_Cert_DuckTail_Entrust_1B59FEA3A77A45F4EF50215669617D38 {
   meta:
      description         = "Detects DuckTail with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-06"
      version             = "1.0"

      hash                = "bc6a58eb83fbefa0d895103e36d53dc6b5178db7ce7576bdba5e5d725acbe34a"
      malware             = "DuckTail"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CONG TY TNHH THUONG MAI DICH VU HP INTERNATIONAL"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "1b:59:fe:a3:a7:7a:45:f4:ef:50:21:56:69:61:7d:38"
      cert_thumbprint     = "BAC9068C9A92697EB8252E2436D222414FDD6067"
      cert_valid_from     = "2023-11-06"
      cert_valid_to       = "2024-11-06"

      country             = "VN"
      state               = "???"
      locality            = "Ho Chi Minh"
      email               = "???"
      rdn_serial_number   = "0317716787"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "1b:59:fe:a3:a7:7a:45:f4:ef:50:21:56:69:61:7d:38"
      )
}
