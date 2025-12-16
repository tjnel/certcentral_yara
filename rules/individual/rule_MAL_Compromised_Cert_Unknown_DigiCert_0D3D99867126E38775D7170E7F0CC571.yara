import "pe"

rule MAL_Compromised_Cert_Unknown_DigiCert_0D3D99867126E38775D7170E7F0CC571 {
   meta:
      description         = "Detects Unknown with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-07"
      version             = "1.0"

      hash                = "acd9cb061a51e93dee4ed4834ae2d946bc9845c0a4904a12fa2a3fbf62b41cb0"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "44.211.848 NICOLAS SAMUEL DE ALMEIDA"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:3d:99:86:71:26:e3:87:75:d7:17:0e:7f:0c:c5:71"
      cert_thumbprint     = "6F7696AFA9722B8E438F0D6E2B6E6B00CAB89F14"
      cert_valid_from     = "2024-10-07"
      cert_valid_to       = "2025-10-06"

      country             = "BR"
      state               = "Minas Gerais"
      locality            = "UBERABA"
      email               = "???"
      rdn_serial_number   = "44.211.848/0001-35"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:3d:99:86:71:26:e3:87:75:d7:17:0e:7f:0c:c5:71"
      )
}
