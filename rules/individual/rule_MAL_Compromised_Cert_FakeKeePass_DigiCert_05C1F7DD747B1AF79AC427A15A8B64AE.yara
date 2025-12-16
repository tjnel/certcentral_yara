import "pe"

rule MAL_Compromised_Cert_FakeKeePass_DigiCert_05C1F7DD747B1AF79AC427A15A8B64AE {
   meta:
      description         = "Detects FakeKeePass with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-31"
      version             = "1.0"

      hash                = "b51dc9ca6f6029a799491bd9b8da18c9d9775116142cedabe958c8bcec96a0f0"
      malware             = "FakeKeePass"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "S.R.L. INT-MCOM"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:c1:f7:dd:74:7b:1a:f7:9a:c4:27:a1:5a:8b:64:ae"
      cert_thumbprint     = "467C6C43E6FBB17FCAEFB46FC41A6B2B829E0EFA"
      cert_valid_from     = "2025-01-31"
      cert_valid_to       = "2026-01-30"

      country             = "MD"
      state               = "???"
      locality            = "Chişinău"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:c1:f7:dd:74:7b:1a:f7:9a:c4:27:a1:5a:8b:64:ae"
      )
}
