import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_7AB21306B11FF280A93FC445876988AB {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-19"
      version             = "1.0"

      hash                = "3d6f88d4ae3da95201d454a65199a8402e1834973c934f5e6658b8964c4d9105"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ABC BIOS d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab"
      cert_thumbprint     = "6D0D10933B355EE2D8701510F22AFF4A06ADBE5B"
      cert_valid_from     = "2021-01-19"
      cert_valid_to       = "2022-01-19"

      country             = "SI"
      state               = "???"
      locality            = "Maribor"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab"
      )
}
