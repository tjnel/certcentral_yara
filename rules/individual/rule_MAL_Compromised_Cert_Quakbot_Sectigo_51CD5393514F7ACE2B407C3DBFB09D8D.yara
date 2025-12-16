import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_51CD5393514F7ACE2B407C3DBFB09D8D {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-23"
      version             = "1.0"

      hash                = "1a49d434e0a95bd312d3d0a6d4fd5335830970bef8009eac1739c27f4986753c"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "APPI CZ a.s"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d"
      cert_thumbprint     = "07A9FD6AF84983DBF083C15983097AC9CE761864"
      cert_valid_from     = "2020-10-23"
      cert_valid_to       = "2021-10-23"

      country             = "CZ"
      state               = "???"
      locality            = "Praha 10 - Malesice"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d"
      )
}
