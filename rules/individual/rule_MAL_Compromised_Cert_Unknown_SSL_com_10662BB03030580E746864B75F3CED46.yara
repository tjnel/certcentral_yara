import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_10662BB03030580E746864B75F3CED46 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-07"
      version             = "1.0"

      hash                = "4a30027501fe373c48c6d484c0b4db59fc23d427814b9d512f20bcbeb4eeff4c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KABA SAFARIS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "10:66:2b:b0:30:30:58:0e:74:68:64:b7:5f:3c:ed:46"
      cert_thumbprint     = "9C4F91294F57D3F77DEC413B8995F80FA73BB313"
      cert_valid_from     = "2025-04-07"
      cert_valid_to       = "2026-04-07"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "10:66:2b:b0:30:30:58:0e:74:68:64:b7:5f:3c:ed:46"
      )
}
