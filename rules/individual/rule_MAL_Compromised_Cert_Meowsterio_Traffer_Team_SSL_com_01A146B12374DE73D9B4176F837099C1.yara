import "pe"

rule MAL_Compromised_Cert_Meowsterio_Traffer_Team_SSL_com_01A146B12374DE73D9B4176F837099C1 {
   meta:
      description         = "Detects Meowsterio Traffer Team with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-28"
      version             = "1.0"

      hash                = "96fd0900a2bf751559dcc6327c15028131c674bf6e4fb7656d762f66897d1211"
      malware             = "Meowsterio Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jianhe Network Technology (Shanghai) Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "01:a1:46:b1:23:74:de:73:d9:b4:17:6f:83:70:99:c1"
      cert_thumbprint     = "7CF0AF8137B3B264DB67CE782084BCAF370340F9"
      cert_valid_from     = "2024-09-28"
      cert_valid_to       = "2025-09-27"

      country             = "CN"
      state               = "???"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310115MA1K42143K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "01:a1:46:b1:23:74:de:73:d9:b4:17:6f:83:70:99:c1"
      )
}
