import "pe"

rule MAL_Compromised_Cert_IcedID_DigiCert_0772B4D1D63233D2B8771997BC8DA5C4 {
   meta:
      description         = "Detects IcedID with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-27"
      version             = "1.0"

      hash                = "600a21358e2cc2d5d50b014c4a4df03435b136bec0ee7903eb88d4368fe37647"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Maya logistika d.o.o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4"
      cert_thumbprint     = "D80719A0FCDE24A6C277CE9187B48D1978F862C2"
      cert_valid_from     = "2021-11-27"
      cert_valid_to       = "2022-10-15"

      country             = "SI"
      state               = "???"
      locality            = "Velenje"
      email               = "???"
      rdn_serial_number   = "6362338000"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4"
      )
}
