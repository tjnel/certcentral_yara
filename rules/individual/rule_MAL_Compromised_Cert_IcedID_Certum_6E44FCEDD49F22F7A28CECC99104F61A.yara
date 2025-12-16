import "pe"

rule MAL_Compromised_Cert_IcedID_Certum_6E44FCEDD49F22F7A28CECC99104F61A {
   meta:
      description         = "Detects IcedID with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-01-05"
      version             = "1.0"

      hash                = "f9fa964ae4dfbf4ecc518fc37985fa5e12bb1059687110d24fb035497940cda3"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "M-Trans Maciej Caban"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6e:44:fc:ed:d4:9f:22:f7:a2:8c:ec:c9:91:04:f6:1a"
      cert_thumbprint     = "C678DCC9D7DA9BDCB75236CB9FA84346AE42704A"
      cert_valid_from     = "2023-01-05"
      cert_valid_to       = "2024-01-05"

      country             = "PL"
      state               = "???"
      locality            = "Skierniewice"
      email               = "???"
      rdn_serial_number   = "389470690"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6e:44:fc:ed:d4:9f:22:f7:a2:8c:ec:c9:91:04:f6:1a"
      )
}
