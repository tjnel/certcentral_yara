import "pe"

rule MAL_Compromised_Cert_CoinLurker_DigiCert_08FD49B1A5ECA2283F3E0971754D2ED4 {
   meta:
      description         = "Detects CoinLurker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-07"
      version             = "1.0"

      hash                = "5b37b7655f7a623694b08101912ca14e4ef3ddd4dd22a1b45a9f92103f299097"
      malware             = "CoinLurker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "武汉薄荷科技有限公司"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:fd:49:b1:a5:ec:a2:28:3f:3e:09:71:75:4d:2e:d4"
      cert_thumbprint     = "8BD9791A4B75106CCBE54E4086205523EA227AEB"
      cert_valid_from     = "2023-12-07"
      cert_valid_to       = "2025-10-09"

      country             = "CN"
      state               = "湖北省"
      locality            = "武汉市"
      email               = "???"
      rdn_serial_number   = "91420106MA4L0NHE9U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:fd:49:b1:a5:ec:a2:28:3f:3e:09:71:75:4d:2e:d4"
      )
}
