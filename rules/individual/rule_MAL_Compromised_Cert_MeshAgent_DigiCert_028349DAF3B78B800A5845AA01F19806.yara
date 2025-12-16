import "pe"

rule MAL_Compromised_Cert_MeshAgent_DigiCert_028349DAF3B78B800A5845AA01F19806 {
   meta:
      description         = "Detects MeshAgent with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-21"
      version             = "1.0"

      hash                = "35896102d20903ff9bab19295e1144f7cff80872749fd875d946b553fbd9302e"
      malware             = "MeshAgent"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TechMonstar LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "02:83:49:da:f3:b7:8b:80:0a:58:45:aa:01:f1:98:06"
      cert_thumbprint     = "3FC97234C39375061E3771C9B0A952CE6E4E478E"
      cert_valid_from     = "2025-11-21"
      cert_valid_to       = "2028-11-20"

      country             = "BD"
      state               = "???"
      locality            = "Dhaka"
      email               = "???"
      rdn_serial_number   = "C-192953"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "02:83:49:da:f3:b7:8b:80:0a:58:45:aa:01:f1:98:06"
      )
}
