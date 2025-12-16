import "pe"

rule MAL_Compromised_Cert_Cobalt_Strike_Sectigo_3A3685FE73DC5C81DA594E0EE949F34B {
   meta:
      description         = "Detects Cobalt Strike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-12-30"
      version             = "1.0"

      hash                = "4376f6c5bd63c9472dc1575b26f70cc2320682a47881e1a9283904bcdec43fd8"
      malware             = "Cobalt Strike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LYDSEC DIGITAL TECHNOLOGY CO., LTD."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "3a:36:85:fe:73:dc:5c:81:da:59:4e:0e:e9:49:f3:4b"
      cert_thumbprint     = "361FE689890D416B5EB4E678CC38F45FA0F2BFD0"
      cert_valid_from     = "2022-12-30"
      cert_valid_to       = "2025-12-29"

      country             = "TW"
      state               = "Taipei"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "3a:36:85:fe:73:dc:5c:81:da:59:4e:0e:e9:49:f3:4b"
      )
}
