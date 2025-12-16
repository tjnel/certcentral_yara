import "pe"

rule MAL_Compromised_Cert_OysterLoader_DigiCert_0ED7F77844A2FA7D73F285219EE1A519 {
   meta:
      description         = "Detects OysterLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "0e68c2fc400036eb279460e37953b1f9db393c6cb8c604ec0504e9de1866ab1c"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "AQUA TRACKSIDE LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0e:d7:f7:78:44:a2:fa:7d:73:f2:85:21:9e:e1:a5:19"
      cert_thumbprint     = "9B841C0D6745420D3902B51938A5C675B21FAB19"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-27"

      country             = "GB"
      state               = "???"
      locality            = "Skelmersdale"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0e:d7:f7:78:44:a2:fa:7d:73:f2:85:21:9e:e1:a5:19"
      )
}
