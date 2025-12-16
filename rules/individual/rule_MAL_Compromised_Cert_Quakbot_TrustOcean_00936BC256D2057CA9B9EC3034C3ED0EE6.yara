import "pe"

rule MAL_Compromised_Cert_Quakbot_TrustOcean_00936BC256D2057CA9B9EC3034C3ED0EE6 {
   meta:
      description         = "Detects Quakbot with compromised cert (TrustOcean)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-28"
      version             = "1.0"

      hash                = "dbac4888cb2be8a41986d0992abcb7215556da786e9b12759f6a39eede97b5f5"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "SALES & MAINTENANCE LIMITED"
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "00:93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6"
      cert_thumbprint     = "CB559881E873DB671F10CFB5929D6750AD08720E"
      cert_valid_from     = "2021-03-28"
      cert_valid_to       = "2022-03-28"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "00:93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6"
      )
}
