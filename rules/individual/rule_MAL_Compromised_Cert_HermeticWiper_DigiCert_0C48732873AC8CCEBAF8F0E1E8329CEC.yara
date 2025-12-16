import "pe"

rule MAL_Compromised_Cert_HermeticWiper_DigiCert_0C48732873AC8CCEBAF8F0E1E8329CEC {
   meta:
      description         = "Detects HermeticWiper with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-13"
      version             = "1.0"

      hash                = "2d29f9ca1d9089ba0399661bb34ba2fd8aba117f04678cd71856d5894aa7150b"
      malware             = "HermeticWiper"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hermetica Digital Ltd"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec"
      cert_thumbprint     = "1AE7556DFACD47D9EFBE79BE974661A5A6D6D923"
      cert_valid_from     = "2021-04-13"
      cert_valid_to       = "2022-04-14"

      country             = "CY"
      state               = "???"
      locality            = "Nicosia"
      email               = "???"
      rdn_serial_number   = "HE 419469"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec"
      )
}
