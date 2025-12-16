import "pe"

rule MAL_Compromised_Cert_Trojan_DigiCert_0144C41E1909E7332C5BA64F0042EE86 {
   meta:
      description         = "Detects Trojan with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-23"
      version             = "1.0"

      hash                = "90465f4f59fc9fb29d12d44765712ce97c3f9cb9067ee33c2d6f2abf88c87190"
      malware             = "Trojan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangxi Yunao Network Technology Co. Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "01:44:c4:1e:19:09:e7:33:2c:5b:a6:4f:00:42:ee:86"
      cert_thumbprint     = "FE186438F2ABEF2DDA453E52E51F852147DE2E7D"
      cert_valid_from     = "2023-05-23"
      cert_valid_to       = "2024-06-14"

      country             = "CN"
      state               = "Guangxi Zhuang Autonomous Region"
      locality            = "Beihai"
      email               = "???"
      rdn_serial_number   = "91450500MAA7H9NJ04"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "01:44:c4:1e:19:09:e7:33:2c:5b:a6:4f:00:42:ee:86"
      )
}
