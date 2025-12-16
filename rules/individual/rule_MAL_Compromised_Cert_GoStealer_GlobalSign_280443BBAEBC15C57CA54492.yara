import "pe"

rule MAL_Compromised_Cert_GoStealer_GlobalSign_280443BBAEBC15C57CA54492 {
   meta:
      description         = "Detects GoStealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "dff89c7a8376baa37c9085a5c20c0a9bd5af6ecce66d6a2ff4f5b6c190d6b562"
      malware             = "GoStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THINK ELLIPSE PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "28:04:43:bb:ae:bc:15:c5:7c:a5:44:92"
      cert_thumbprint     = "EA007932C2326F256A0C63F0A95BCFA86C8DC544"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-11"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "ceothinkellips@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "28:04:43:bb:ae:bc:15:c5:7c:a5:44:92"
      )
}
