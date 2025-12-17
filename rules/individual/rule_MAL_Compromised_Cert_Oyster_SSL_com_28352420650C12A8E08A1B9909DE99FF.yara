import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_28352420650C12A8E08A1B9909DE99FF {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-08"
      version             = "1.0"

      hash                = "067f6c9d36af9d3c088a37151721eb4981dde65c549d22b5a3ada0b90441e571"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "P M-Soft v/Per Mortensen"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:35:24:20:65:0c:12:a8:e0:8a:1b:99:09:de:99:ff"
      cert_thumbprint     = "984CA1B6801E7109D4074D6BFC2B606B9DAC363A"
      cert_valid_from     = "2025-08-08"
      cert_valid_to       = "2026-08-08"

      country             = "DK"
      state               = "Region Zealand"
      locality            = "Nykøbing Falster"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:35:24:20:65:0c:12:a8:e0:8a:1b:99:09:de:99:ff"
      )
}
