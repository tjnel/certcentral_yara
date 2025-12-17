import "pe"

rule MAL_Compromised_Cert_IcedID_DigiCert_0406C4A1521A38C8D0C4AA214388E4DC {
   meta:
      description         = "Detects IcedID with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-01-11"
      version             = "1.0"

      hash                = "4de5453891027cc3a82f3e72a71c774ae95e6b6d4587197056cf4fdc85947e14"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Venezia Design SRL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc"
      cert_thumbprint     = "097B93B2E0520A2D686B4A6595220DE12C66AE0C"
      cert_valid_from     = "2022-01-11"
      cert_valid_to       = "2023-01-11"

      country             = "RO"
      state               = "???"
      locality            = "Bucuresti"
      email               = "???"
      rdn_serial_number   = "J40/12053/2015"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc"
      )
}
