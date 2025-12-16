import "pe"

rule MAL_Compromised_Cert_OysterLoader_DigiCert_05E4DF61BA3ED3493ACC12C5AAF7F04B {
   meta:
      description         = "Detects OysterLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-06"
      version             = "1.0"

      hash                = "cc1dae253b72906cfe2e89c278ab45a9ccc63567919373de7600783a05dd6d0a"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "SWS SOFT SRL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:e4:df:61:ba:3e:d3:49:3a:cc:12:c5:aa:f7:f0:4b"
      cert_thumbprint     = "A4D933F8396BE233E86F7F09D4312DAD5F55C3EE"
      cert_valid_from     = "2024-12-06"
      cert_valid_to       = "2025-12-05"

      country             = "MD"
      state               = "???"
      locality            = "Chişinău"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:e4:df:61:ba:3e:d3:49:3a:cc:12:c5:aa:f7:f0:4b"
      )
}
