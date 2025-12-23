import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_084C51D816E60BEBC5B0620E6561C3C9 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-18"
      version             = "1.0"

      hash                = "c53548839a08506275c03d0d5d21b9a85a5999fbad9dcf39a4d9556b5d18dbfb"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "Malware was distributed disguised as a video. It reaches out to telegram to send information about the infection: https://app.any.run/tasks/42464132-b230-4f43-a233-bff356d8fce4?malconf=true"

      signer              = "John Norman Grimsey"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "08:4c:51:d8:16:e6:0b:eb:c5:b0:62:0e:65:61:c3:c9"
      cert_thumbprint     = "A86E33888307FF85EE1F65AD26DC72F311A10513"
      cert_valid_from     = "2025-11-18"
      cert_valid_to       = "2026-11-17"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "08:4c:51:d8:16:e6:0b:eb:c5:b0:62:0e:65:61:c3:c9"
      )
}
