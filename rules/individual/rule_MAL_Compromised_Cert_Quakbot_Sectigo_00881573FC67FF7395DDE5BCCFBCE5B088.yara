import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00881573FC67FF7395DDE5BCCFBCE5B088 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-03"
      version             = "1.0"

      hash                = "de9738c0910931b2b5e1f68841637a25301d17ab3860cd6e2cc1cbef9af1f5dd"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Trade in Brasil s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"
      cert_thumbprint     = "31B3A3C173C2A2D1086794BFC8D853E25E62FB46"
      cert_valid_from     = "2021-05-03"
      cert_valid_to       = "2022-05-03"

      country             = "SK"
      state               = "Bratislavský kraj"
      locality            = "mestská časť Nové Mesto"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"
      )
}
