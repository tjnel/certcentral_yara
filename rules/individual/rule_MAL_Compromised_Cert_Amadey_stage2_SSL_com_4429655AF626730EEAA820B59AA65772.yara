import "pe"

rule MAL_Compromised_Cert_Amadey_stage2_SSL_com_4429655AF626730EEAA820B59AA65772 {
   meta:
      description         = "Detects Amadey_stage2 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "37c5723aeb725b1aec98da1f776fd841176c687d8ad5c2a14a6ebd831f1615d1"
      malware             = "Amadey_stage2"
      malware_type        = "Unknown"
      malware_notes       = "Hidden VNC tool"

      signer              = "Horvath Brigitta Tinterne"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "44:29:65:5a:f6:26:73:0e:ea:a8:20:b5:9a:a6:57:72"
      cert_thumbprint     = "B2BB4C27712CC4EBEEE82969D1DBF04D78562875"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2026-09-30"

      country             = "HU"
      state               = "Budapest"
      locality            = "Budapest"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "44:29:65:5a:f6:26:73:0e:ea:a8:20:b5:9a:a6:57:72"
      )
}
