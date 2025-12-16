import "pe"

rule MAL_Compromised_Cert_FatalRAT_Certum_6C162B47BDE6ABB337796A32ACEAEB3A {
   meta:
      description         = "Detects FatalRAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-11"
      version             = "1.0"

      hash                = "789bfb11d716ca32514829b125c056395ce3b6234d56a831570c624f8a684e24"
      malware             = "FatalRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Beijing Jianguang Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6c:16:2b:47:bd:e6:ab:b3:37:79:6a:32:ac:ea:eb:3a"
      cert_thumbprint     = "664CB4E2695B7C17337CB5D7C9E2D38BEB274EF2"
      cert_valid_from     = "2024-07-11"
      cert_valid_to       = "2025-07-11"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110106MA00BTU826"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6c:16:2b:47:bd:e6:ab:b3:37:79:6a:32:ac:ea:eb:3a"
      )
}
