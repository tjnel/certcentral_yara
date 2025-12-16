import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_DigiCert_0BDA674CF2E047F94E18FA1DA5356AEA {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-22"
      version             = "1.0"

      hash                = "41849f9995d6ee46154e2b3ad48c64546c14de8e47930819335893c319ea3dab"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brave Exhibits Inc"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:da:67:4c:f2:e0:47:f9:4e:18:fa:1d:a5:35:6a:ea"
      cert_thumbprint     = "1C59C9C28A403EC8B34C469D90C969DB25B423CC"
      cert_valid_from     = "2025-10-22"
      cert_valid_to       = "2026-10-21"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:da:67:4c:f2:e0:47:f9:4e:18:fa:1d:a5:35:6a:ea"
      )
}
