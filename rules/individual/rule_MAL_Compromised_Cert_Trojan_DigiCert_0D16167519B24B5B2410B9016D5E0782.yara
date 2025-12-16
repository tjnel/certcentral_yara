import "pe"

rule MAL_Compromised_Cert_Trojan_DigiCert_0D16167519B24B5B2410B9016D5E0782 {
   meta:
      description         = "Detects Trojan with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-30"
      version             = "1.0"

      hash                = "42c3483fbf438233db25a0fbdc8636ac3e6bfe374fdd929b2c0fcbc108a45c6a"
      malware             = "Trojan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangxi Yunao Network Technology Co., Ltd."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:16:16:75:19:b2:4b:5b:24:10:b9:01:6d:5e:07:82"
      cert_thumbprint     = "492c5d36b26fb2b1931805580f0630a6807d27cc8ac53fd4e6634e62e84ebfa9"
      cert_valid_from     = "2022-05-30"
      cert_valid_to       = "2023-05-30"

      country             = "CN"
      state               = "Guangxi"
      locality            = "Beihai"
      email               = "???"
      rdn_serial_number   = "91450500MAA7H9NJ04"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:16:16:75:19:b2:4b:5b:24:10:b9:01:6d:5e:07:82"
      )
}
