import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_3BCAED3EF678F2F9BF38D09E149B8D70 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-03"
      version             = "1.0"

      hash                = "78749911faeac0032bb0c8562761fa6ee3fb85f37e099f5169d9dcc29c8024bd"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "StarY Media Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70"
      cert_thumbprint     = "18BE3EEAE77E60744FFA1D3DB4E3B47DF9C7F28E"
      cert_valid_from     = "2020-09-03"
      cert_valid_to       = "2021-09-03"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70"
      )
}
