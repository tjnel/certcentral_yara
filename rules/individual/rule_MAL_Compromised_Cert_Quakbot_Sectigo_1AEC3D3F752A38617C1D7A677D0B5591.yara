import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1AEC3D3F752A38617C1D7A677D0B5591 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-27"
      version             = "1.0"

      hash                = "c9c640e28bf179489b862381ef3e20c50a2557d76e6f165968433753d6e78d60"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SILVER d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91"
      cert_thumbprint     = "1D41B9F7714F221D76592E403D2FBB0F0310E697"
      cert_valid_from     = "2021-01-27"
      cert_valid_to       = "2022-01-27"

      country             = "SI"
      state               = "???"
      locality            = "Novo mesto"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91"
      )
}
