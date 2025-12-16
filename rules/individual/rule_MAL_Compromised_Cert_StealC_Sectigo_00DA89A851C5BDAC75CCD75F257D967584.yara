import "pe"

rule MAL_Compromised_Cert_StealC_Sectigo_00DA89A851C5BDAC75CCD75F257D967584 {
   meta:
      description         = "Detects StealC with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "b8a874e4883d21fd03434c97cf5d5a80b9085924760c273483a9f7723c864e0a"
      malware             = "StealC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KrsuoJohce MonovaTech Information Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:da:89:a8:51:c5:bd:ac:75:cc:d7:5f:25:7d:96:75:84"
      cert_thumbprint     = "B882F3F37C0ED6AF37EB39CB9A835DBC87202AA5"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91370203MA3N99947C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:da:89:a8:51:c5:bd:ac:75:cc:d7:5f:25:7d:96:75:84"
      )
}
