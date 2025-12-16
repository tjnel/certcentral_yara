import "pe"

rule MAL_Compromised_Cert_IcedID_Certum_2A2F270535C2D5E7630720FB229B5D1C {
   meta:
      description         = "Detects IcedID with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-18"
      version             = "1.0"

      hash                = "3f38ae75758c8afb75b0660a7c927ccb2bce73f572a9e105ea2288f1288f682b"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "KOZUZ SP. Z O.O."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2a:2f:27:05:35:c2:d5:e7:63:07:20:fb:22:9b:5d:1c"
      cert_thumbprint     = "BA0B1AB0AE84B9DB98D679D13BC905C39CBE55F6"
      cert_valid_from     = "2023-05-18"
      cert_valid_to       = "2024-05-17"

      country             = "PL"
      state               = "świętokrzyskie"
      locality            = "Starachowice"
      email               = "???"
      rdn_serial_number   = "0001028448"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2a:2f:27:05:35:c2:d5:e7:63:07:20:fb:22:9b:5d:1c"
      )
}
