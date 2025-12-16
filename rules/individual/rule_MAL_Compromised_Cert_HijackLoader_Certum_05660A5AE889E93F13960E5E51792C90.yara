import "pe"

rule MAL_Compromised_Cert_HijackLoader_Certum_05660A5AE889E93F13960E5E51792C90 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-10"
      version             = "1.0"

      hash                = "104f8ddf10d61108a7815aa33690eff037ac6fcd7528c4c4a45a202b71d91093"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shenzhen Wanzhong Yunfu Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "05:66:0a:5a:e8:89:e9:3f:13:96:0e:5e:51:79:2c:90"
      cert_thumbprint     = "400C13D6F6BFB18A4645B79067ED3580A847E2AC"
      cert_valid_from     = "2024-09-10"
      cert_valid_to       = "2025-09-10"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5DNQ4T71"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "05:66:0a:5a:e8:89:e9:3f:13:96:0e:5e:51:79:2c:90"
      )
}
