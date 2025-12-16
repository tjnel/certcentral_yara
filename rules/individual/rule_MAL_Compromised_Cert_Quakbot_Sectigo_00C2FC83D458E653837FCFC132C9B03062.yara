import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00C2FC83D458E653837FCFC132C9B03062 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-09"
      version             = "1.0"

      hash                = "dcda70b5cc63629dd2760dbc76ffda0bedefd0ee92af4d4e3740acc7dd2eaff2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Vertical"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
      cert_thumbprint     = "3B49AE9768E845E6225D3DC8FF347CB2607FF052"
      cert_valid_from     = "2020-10-09"
      cert_valid_to       = "2021-10-09"

      country             = "RU"
      state               = "???"
      locality            = "Moskva"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
      )
}
