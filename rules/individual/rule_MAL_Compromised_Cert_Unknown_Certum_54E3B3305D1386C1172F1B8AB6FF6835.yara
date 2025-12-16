import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_54E3B3305D1386C1172F1B8AB6FF6835 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-07"
      version             = "1.0"

      hash                = "2b587ca6eb1af162951ade0e214b856f558cc859ae1a8674646f853661704211"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Yantai Guanlian Logistics Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "54:e3:b3:30:5d:13:86:c1:17:2f:1b:8a:b6:ff:68:35"
      cert_thumbprint     = "7D495C559D33D85A466ED3381FA96FA72F653E41"
      cert_valid_from     = "2024-08-07"
      cert_valid_to       = "2025-08-07"

      country             = "CN"
      state               = "Shandong"
      locality            = "Yantai"
      email               = "???"
      rdn_serial_number   = "91370611MA3TWX1N8R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "54:e3:b3:30:5d:13:86:c1:17:2f:1b:8a:b6:ff:68:35"
      )
}
