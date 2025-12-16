import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_DigiCert_03A656478B714A24DD5DAF98F68E878B {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-12"
      version             = "1.0"

      hash                = "af143b79a29e51366964416da4b3a30b26def93d52b67a6ad6e9528935bf4a62"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "FILIPA S.R.L."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "03:a6:56:47:8b:71:4a:24:dd:5d:af:98:f6:8e:87:8b"
      cert_thumbprint     = "938EDBA2A0B446E6FE094E15075EE612DCE53A7E"
      cert_valid_from     = "2025-09-12"
      cert_valid_to       = "2026-09-11"

      country             = "AR"
      state               = "???"
      locality            = "Buenos Aires"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "03:a6:56:47:8b:71:4a:24:dd:5d:af:98:f6:8e:87:8b"
      )
}
