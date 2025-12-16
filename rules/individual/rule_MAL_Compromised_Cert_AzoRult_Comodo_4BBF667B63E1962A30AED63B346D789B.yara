import "pe"

rule MAL_Compromised_Cert_AzoRult_Comodo_4BBF667B63E1962A30AED63B346D789B {
   meta:
      description         = "Detects AzoRult with compromised cert (Comodo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2018-08-15"
      version             = "1.0"

      hash                = "43d18cfc97f95e81d5f92b327714ecbb42c2deaca0cbbedca9739909daff5267"
      malware             = "AzoRult"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MONITOR, LLC"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "4b:bf:66:7b:63:e1:96:2a:30:ae:d6:3b:34:6d:78:9b"
      cert_thumbprint     = "27CA54EE5BB0DC64978ADA5090E351FB045287C5"
      cert_valid_from     = "2018-08-15"
      cert_valid_to       = "2019-09-28"

      country             = "RU"
      state               = "Saint-Petersburg"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "4b:bf:66:7b:63:e1:96:2a:30:ae:d6:3b:34:6d:78:9b"
      )
}
