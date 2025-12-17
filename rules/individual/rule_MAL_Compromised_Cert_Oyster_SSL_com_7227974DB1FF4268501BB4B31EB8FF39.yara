import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_7227974DB1FF4268501BB4B31EB8FF39 {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-04"
      version             = "1.0"

      hash                = "31ebdf2d6fb973f648c05226b57ff264d8b650dfe03f995deba0fa795d76f37c"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "4th State Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "72:27:97:4d:b1:ff:42:68:50:1b:b4:b3:1e:b8:ff:39"
      cert_thumbprint     = "24010C3BA7C765BF2F46DE1D2412736CF869A0FE"
      cert_valid_from     = "2025-09-04"
      cert_valid_to       = "2026-09-04"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "72:27:97:4d:b1:ff:42:68:50:1b:b4:b3:1e:b8:ff:39"
      )
}
