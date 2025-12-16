import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Phishing_Verokey_0126669732ACEC9B2FD03AE3C0C4F6D0 {
   meta:
      description         = "Detects ScreenConnect Phishing with compromised cert (Verokey)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-19"
      version             = "1.0"

      hash                = "45d72b8c68d7c80833c08fd87dc11b60b277098df860f1d4f509fb561fa29e32"
      malware             = "ScreenConnect Phishing"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Babaian tech LLC."
      cert_issuer_short   = "Verokey"
      cert_issuer         = "Verokey High Assurance Secure Code EV"
      cert_serial         = "01:26:66:97:32:ac:ec:9b:2f:d0:3a:e3:c0:c4:f6:d0"
      cert_thumbprint     = "A4177F522638026FEDE55003DFC5475F890DF43A"
      cert_valid_from     = "2025-08-19"
      cert_valid_to       = "2026-08-18"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Verokey High Assurance Secure Code EV" and
         sig.serial == "01:26:66:97:32:ac:ec:9b:2f:d0:3a:e3:c0:c4:f6:d0"
      )
}
