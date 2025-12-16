import "pe"

rule MAL_Compromised_Cert_IcedID_DigiCert_06BCB74291D96096577BDB1E165DCE85 {
   meta:
      description         = "Detects IcedID with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-27"
      version             = "1.0"

      hash                = "074cef597dc028b08dc2fe927ea60f09cfd5e19f928f2e4071860b9a159b365d"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Revo Security SRL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85"
      cert_thumbprint     = "D1BDE6303266977F7540221543D3F2625DA24AC4"
      cert_valid_from     = "2021-11-27"
      cert_valid_to       = "2022-11-24"

      country             = "RO"
      state               = "???"
      locality            = "Videle"
      email               = "???"
      rdn_serial_number   = "J34/641/2017"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85"
      )
}
