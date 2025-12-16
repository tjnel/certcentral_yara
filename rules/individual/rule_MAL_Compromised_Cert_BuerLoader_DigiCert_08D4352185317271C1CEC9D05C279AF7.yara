import "pe"

rule MAL_Compromised_Cert_BuerLoader_DigiCert_08D4352185317271C1CEC9D05C279AF7 {
   meta:
      description         = "Detects BuerLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-05"
      version             = "1.0"

      hash                = "4332bb07339c3096997fbb89b695afeb3b1e21632c8ecb4e144ec883d61ab066"
      malware             = "BuerLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Retalit LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7"
      cert_thumbprint     = "52FE4ECD6C925E89068FEE38F1B9A669A70F8BAB"
      cert_valid_from     = "2020-08-05"
      cert_valid_to       = "2021-07-12"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "1177847253540"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7"
      )
}
