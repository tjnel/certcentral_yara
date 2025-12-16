import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D4EF1AB6AB5D3CB35E4EFB7984DEF7A2 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-01-21"
      version             = "1.0"

      hash                = "309bca5d9fde32746cd61a7ea4b2da3ef8f6cf2de57ee40e835c1b26237c991a"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "REIGN BROS ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2"
      cert_thumbprint     = "10D82C75A1846EBFB2A0D1ABE9C01622BDFABF0A"
      cert_valid_from     = "2021-01-21"
      cert_valid_to       = "2022-01-21"

      country             = "DK"
      state               = "???"
      locality            = "København K"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2"
      )
}
