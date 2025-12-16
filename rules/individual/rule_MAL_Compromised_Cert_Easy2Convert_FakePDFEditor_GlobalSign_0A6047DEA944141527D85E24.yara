import "pe"

rule MAL_Compromised_Cert_Easy2Convert_FakePDFEditor_GlobalSign_0A6047DEA944141527D85E24 {
   meta:
      description         = "Detects Easy2Convert_FakePDFEditor with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-01"
      version             = "1.0"

      hash                = "27262f4bf8096f04e53309d4ce603cfbeb27ed10abdf1c461d3ccb14e012f61e"
      malware             = "Easy2Convert_FakePDFEditor"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BLUE TAKIN LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0a:60:47:de:a9:44:14:15:27:d8:5e:24"
      cert_thumbprint     = "A6BD7B323D3135E4F13F5C198EA23163D622B538"
      cert_valid_from     = "2025-04-01"
      cert_valid_to       = "2026-04-02"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Tel Aviv"
      email               = "support@bluetakin.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0a:60:47:de:a9:44:14:15:27:d8:5e:24"
      )
}
