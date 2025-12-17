import "pe"

rule MAL_Compromised_Cert_ResidentialProxyInstaller_DigiCert_0A8AAD8C6E69D0EA3072E6EEA5FBD468 {
   meta:
      description         = "Detects ResidentialProxyInstaller with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-20"
      version             = "1.0"

      hash                = "cad92559e7848f000ca084aa6e5434a2eafedd2bc2e5ff06a13b724bfd447359"
      malware             = "ResidentialProxyInstaller"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Agora International Agency Bilisim Hizmetleri Limited Sirketi"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:8a:ad:8c:6e:69:d0:ea:30:72:e6:ee:a5:fb:d4:68"
      cert_thumbprint     = "cb26fe91f122ae7a0873085a5bf6de9361fa124fe1c57cd1e2e942fc991cc52c"
      cert_valid_from     = "2023-09-20"
      cert_valid_to       = "2026-08-31"

      country             = "TR"
      state               = "İstanbul"
      locality            = "Kadıköy"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:8a:ad:8c:6e:69:d0:ea:30:72:e6:ee:a5:fb:d4:68"
      )
}
