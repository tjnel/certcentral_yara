import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_DigiCert_0A04CAF1BB3BC17A33C6E155EC4F5883 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-10"
      version             = "1.0"

      hash                = "945d0516c078c0255dfb8476056580daee0309bf6cc4bb1542671686e42d85ff"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Keroro Software LLC"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Global G3 Code Signing ECC SHA384 2021 CA1"
      cert_serial         = "0a:04:ca:f1:bb:3b:c1:7a:33:c6:e1:55:ec:4f:58:83"
      cert_thumbprint     = "07AAE8AA3A5356061AC23E963CA76156351737D2"
      cert_valid_from     = "2025-07-10"
      cert_valid_to       = "2028-09-26"

      country             = "CN"
      state               = "广东省"
      locality            = "深圳市"
      email               = "???"
      rdn_serial_number   = "91440300MA5FAR1W6E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Global G3 Code Signing ECC SHA384 2021 CA1" and
         sig.serial == "0a:04:ca:f1:bb:3b:c1:7a:33:c6:e1:55:ec:4f:58:83"
      )
}
